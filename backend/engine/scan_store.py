"""Persistent scan jobs and relational ECDAT V4 database store. Run one API process; worker threads are bounded."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
import secrets
import sqlite3
import threading
from typing import Any, Dict, List, Optional
import uuid

from .asset_graph import AssetGraphService, CryptoAsset
from .evidence_fusion import EvidenceFusionEngine
from .evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType, Provenance
from .scan_manifest import ScanManifest


def now():
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    def __init__(self, path=None):
        self.path = path or os.getenv('ECDAT_DB', 'data/scans.sqlite3')
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self.pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix='scan')
        self.lock = threading.Lock()
        with self.connect() as db:
            # 1. Existing baseline tables
            db.execute('''CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY, project TEXT NOT NULL, kind TEXT NOT NULL,
                status TEXT NOT NULL, created_at TEXT NOT NULL, finished_at TEXT,
                input_hash TEXT NOT NULL, payload TEXT, result TEXT, error TEXT)''')
            db.execute('''CREATE TABLE IF NOT EXISTS migration_plans (
                id TEXT PRIMARY KEY, project TEXT NOT NULL, created_at TEXT NOT NULL,
                result TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT,
                organization TEXT, environment TEXT NOT NULL,
                business_criticality TEXT NOT NULL, data_sensitivity TEXT NOT NULL,
                data_lifetime_years INTEGER NOT NULL, migration_target_date TEXT,
                owner TEXT, tags TEXT NOT NULL, is_demo INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
                role TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)''')

            # 2. ECDAT V4 Reproducibility Manifests
            db.execute('''CREATE TABLE IF NOT EXISTS scan_manifests (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                input_hash TEXT NOT NULL,
                scanner_version TEXT NOT NULL,
                configuration_hash TEXT NOT NULL,
                result_hash TEXT,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)''')

            # 3. ECDAT V4 Relational Crypto Asset Graph
            db.execute('''CREATE TABLE IF NOT EXISTS crypto_assets (
                id TEXT PRIMARY KEY,
                project TEXT NOT NULL,
                scan_id TEXT,
                asset_type TEXT NOT NULL,
                name TEXT NOT NULL,
                algorithm TEXT,
                variant TEXT,
                key_size INTEGER,
                library TEXT,
                version TEXT,
                artifact_id TEXT,
                status TEXT NOT NULL DEFAULT 'ACTIVE',
                fused_status TEXT NOT NULL DEFAULT 'SINGLE_SOURCE',
                highest_evidence_level TEXT NOT NULL DEFAULT 'E0',
                confidence REAL NOT NULL DEFAULT 0.0,
                explanation TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE SET NULL)''')

            # 4. ECDAT V4 Unified Evidence Store
            db.execute('''CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                asset_id TEXT,
                scan_id TEXT NOT NULL,
                project TEXT NOT NULL,
                state TEXT NOT NULL,
                level TEXT NOT NULL,
                confidence REAL NOT NULL,
                source_engine TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                rule_id TEXT,
                rule_version TEXT,
                observation_type TEXT NOT NULL,
                artifact_type TEXT NOT NULL,
                file_path TEXT,
                line_start INTEGER,
                line_end INTEGER,
                byte_offset TEXT,
                symbol TEXT,
                description TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)''')

            # 5. ECDAT V4 Graph Edges
            db.execute('''CREATE TABLE IF NOT EXISTS graph_edges (
                id TEXT PRIMARY KEY,
                project TEXT NOT NULL,
                scan_id TEXT,
                source_id TEXT NOT NULL,
                source_type TEXT NOT NULL,
                relationship TEXT NOT NULL,
                target_id TEXT NOT NULL,
                target_type TEXT NOT NULL,
                evidence_id TEXT,
                confidence REAL NOT NULL DEFAULT 1.0,
                created_at TEXT NOT NULL,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE,
                FOREIGN KEY(evidence_id) REFERENCES evidence(id) ON DELETE SET NULL)''')

            # 6. ECDAT V4 Crypto Risk & PQC Readiness Intelligence
            db.execute('''CREATE TABLE IF NOT EXISTS risk_assessments (
                assessment_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                scan_id TEXT,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                knowledge_base_version TEXT NOT NULL,
                engine_version TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)''')

            db.execute('''CREATE TABLE IF NOT EXISTS pqc_readiness (
                assessment_id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                scan_id TEXT,
                overall TEXT NOT NULL,
                knowledge_base_version TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE)''')

            db.execute('''CREATE TABLE IF NOT EXISTS hndl_assessments (
                asset_id TEXT PRIMARY KEY,
                state TEXT NOT NULL,
                data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE)''')

            # 7. Performance Indexes
            db.execute('CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_manifests_scan ON scan_manifests(scan_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_assets_project ON crypto_assets(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_assets_scan ON crypto_assets(scan_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_assets_algo ON crypto_assets(algorithm)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_evidence_asset ON evidence(asset_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_evidence_project ON evidence(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_evidence_level_state ON evidence(level, state)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_edges_project ON graph_edges(project)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_edges_source ON graph_edges(source_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_edges_target ON graph_edges(target_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_edges_rel ON graph_edges(relationship)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_risk_asset ON risk_assessments(asset_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_risk_scan ON risk_assessments(scan_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_pqc_asset ON pqc_readiness(asset_id)')
            db.execute('CREATE INDEX IF NOT EXISTS idx_pqc_scan ON pqc_readiness(scan_id)')

            # Mark interrupted jobs as failed on restart
            db.execute("UPDATE scans SET status='failed', error='Worker interrupted; submit again', finished_at=? WHERE status IN ('queued','running')", (now(),))
            self._ensure_default_project(db)
            self._ensure_demo_user(db)

        self.graph = AssetGraphService(self.connect)
        self.fusion = EvidenceFusionEngine(self.graph)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON;')
        db.execute('PRAGMA journal_mode = WAL;')
        return db

    @staticmethod
    def _ensure_default_project(db):
        timestamp = now()
        db.execute(
            '''INSERT OR IGNORE INTO projects VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            ('default', 'ECDAT Default Project', 'Default cryptographic discovery workspace',
             'ECDAT', 'Production', 'Critical', 'Sensitive', 20, '2030-01-01',
             'Security Team', '["default"]', 1, timestamp, timestamp),
        )

    @classmethod
    def _ensure_demo_user(cls, db):
        timestamp = now()
        db.execute(
            'INSERT OR IGNORE INTO users VALUES (?,?,?,?,?,?)',
            ('admin', 'admin@ecdat.local', 'ECDAT Administrator', 'OWNER',
             cls._hash_password('admin123'), timestamp),
        )

    @staticmethod
    def _hash_password(password, salt=None):
        salt_bytes = bytes.fromhex(salt) if salt else os.urandom(16)
        digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt_bytes, 240_000)
        return f'{salt_bytes.hex()}:{digest.hex()}'

    def authenticate_user(self, email, password):
        with self.connect() as db:
            row = db.execute('SELECT * FROM users WHERE lower(email)=lower(?)', (email,)).fetchone()
        if not row:
            return None
        salt, _ = row['password_hash'].split(':', 1)
        if not secrets.compare_digest(self._hash_password(password, salt), row['password_hash']):
            return None
        return {key: row[key] for key in ('id', 'email', 'name', 'role')}

    def create_user(self, email, name, role, password):
        user_id = str(uuid.uuid4())
        try:
            with self.connect() as db:
                db.execute('INSERT INTO users VALUES (?,?,?,?,?,?)',
                           (user_id, email.lower(), name, role, self._hash_password(password), now()))
        except sqlite3.IntegrityError as exc:
            raise ValueError('An account with this email already exists') from exc
        return {'id': user_id, 'email': email.lower(), 'name': name, 'role': role}

    def list_projects(self):
        with self.connect() as db:
            rows = db.execute('SELECT * FROM projects ORDER BY created_at DESC').fetchall()
        return [self._project_dict(row) for row in rows]

    def get_project(self, project_id):
        with self.connect() as db:
            row = db.execute('SELECT * FROM projects WHERE id=?', (project_id,)).fetchone()
        return self._project_dict(row) if row else None

    def save_project(self, value, create=False):
        project_id = value['id']
        existing = self.get_project(project_id)
        if create and existing:
            raise ValueError('Project already exists')
        timestamp = now()
        merged = {
            'id': project_id,
            'name': project_id,
            'description': '',
            'organization': '',
            'environment': 'Production',
            'business_criticality': 'Unknown',
            'data_sensitivity': 'Unknown',
            'data_lifetime_years': 10,
            'migration_target_date': None,
            'owner': None,
            'tags': [],
            'is_demo': False,
            'created_at': timestamp,
            **(existing or {}),
            **value,
            'updated_at': timestamp,
        }
        with self.connect() as db:
            db.execute(
                '''INSERT OR REPLACE INTO projects
                   (id,name,description,organization,environment,business_criticality,
                    data_sensitivity,data_lifetime_years,migration_target_date,owner,tags,
                    is_demo,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                (merged['id'], merged['name'], merged['description'], merged['organization'],
                 merged['environment'], merged['business_criticality'], merged['data_sensitivity'],
                 merged['data_lifetime_years'], merged['migration_target_date'], merged['owner'],
                 json.dumps(merged['tags']), int(merged['is_demo']), merged['created_at'], timestamp),
            )
        return self.get_project(project_id)

    def _project_dict(self, row):
        value = dict(row)
        value['tags'] = json.loads(value.get('tags') or '[]')
        value['is_demo'] = bool(value.get('is_demo'))
        with self.connect() as db:
            scan_row = db.execute(
                'SELECT count(*) count, max(created_at) last_scan_at FROM scans WHERE project=?',
                (value['id'],),
            ).fetchone()
            asset_count = db.execute(
                'SELECT count(*) FROM crypto_assets WHERE project=?', (value['id'],)
            ).fetchone()[0]
            risk_count = db.execute(
                "SELECT count(*) FROM crypto_assets WHERE project=? AND lower(coalesce(algorithm,'')) IN ('rsa','ecdsa','dh','ecdh')",
                (value['id'],),
            ).fetchone()[0]
        value['metrics'] = {
            'asset_count': asset_count,
            'scan_count': scan_row['count'],
            'quantum_risk_count': risk_count,
            'last_scan_at': scan_row['last_scan_at'],
        }
        return value

    def submit(self, project, kind, payload, worker):
        encoded = json.dumps(payload, sort_keys=True)
        scan_id = str(uuid.uuid4())
        input_hash = hashlib.sha256(encoded.encode()).hexdigest()
        with self.lock, self.connect() as db:
            count = db.execute("SELECT count(*) FROM scans WHERE status IN ('queued','running')").fetchone()[0]
            if count >= 20:
                raise ValueError('Scan queue is full; retry later')
            db.execute('INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?,?)',
                       (scan_id, project, kind, 'queued', now(), None,
                        input_hash, encoded, None, None))
        self.pool.submit(self._run, scan_id, project, payload, input_hash, worker)
        return self.get(scan_id, project)

    def _run(self, scan_id, project, payload, input_hash, worker):
        with self.connect() as db:
            changed = db.execute("UPDATE scans SET status='running' WHERE id=? AND status='queued'", (scan_id,)).rowcount
        if not changed:
            return
        manifest = ScanManifest(
            scan_id=scan_id,
            input_hash=input_hash,
            configuration=payload if isinstance(payload, dict) else {},
        )
        try:
            result = worker(payload)
            status = 'failed' if result.get('status') == 'error' else 'completed'
            error = result.get('error')

            if status == 'completed' and isinstance(result, dict):
                # Normalize and fuse evidence records into CryptoAsset Graph
                raw_ev_list = result.get('evidence', [])
                parsed_ev = []
                for item in raw_ev_list:
                    if isinstance(item, dict):
                        # Ensure scan_id is attributed
                        if 'provenance' in item and isinstance(item['provenance'], dict):
                            item['provenance']['scan_id'] = scan_id
                        parsed_ev.append(Evidence.from_dict(item))
                    elif isinstance(item, Evidence):
                        item.provenance.scan_id = scan_id
                        parsed_ev.append(item)

                if parsed_ev:
                    fused_assets = self.fusion.fuse_scan_evidence(project, scan_id, parsed_ev)
                    result['fused_assets'] = [a.to_dict() for a in fused_assets]
                    try:
                        from .intelligence.intelligence_pipeline import evaluate_asset
                        for a in fused_assets:
                            ev_list = self.graph.get_asset_evidence(a.id)
                            eval_report = evaluate_asset(a.to_dict(), ev_list)
                            self.graph.save_risk_assessment(eval_report)
                    except Exception:
                        pass

                # Connect call graph edges to asset graph
                try:
                    if result and isinstance(result, dict) and 'call_graph' in result:
                        for call in result.get('call_graph', []):
                            caller = call.get('caller')
                            callee = call.get('callee')
                            file_path = call.get('file', '')
                            if caller and callee and caller != "<global>":
                                caller_id = f"svc-{project}-{caller.lower()}"
                                if not self.graph.get_asset(caller_id, project):
                                    self.graph.create_asset(
                                        project,
                                        AssetType.SERVICE,
                                        caller,
                                        scan_id=scan_id,
                                        asset_id=caller_id,
                                    )
                                callee_norm = callee.lower().replace(" ", "_").replace("-", "_")
                                target_id = f"asset-{project}-{callee_norm}"
                                if not self.graph.get_asset(target_id, project):
                                    self.graph.create_asset(
                                        project,
                                        AssetType.ALGORITHM,
                                        callee,
                                        scan_id=scan_id,
                                        algorithm=callee,
                                        asset_id=target_id,
                                    )
                                self.graph.add_relationship(
                                    project=project,
                                    source_id=caller_id,
                                    source_type="SERVICE",
                                    relationship=RelationshipType.CALLS,
                                    target_id=target_id,
                                    target_type="ALGORITHM",
                                    scan_id=scan_id,
                                )

                except Exception:
                    pass


                # Compute reproducible result hash and save ScanManifest
                manifest.finalize_result(result)
                self.save_manifest(manifest)

        except Exception as exc:
            result, status, error = None, 'failed', str(exc)
        with self.connect() as db:
            db.execute("UPDATE scans SET status=?, result=?, error=?, finished_at=? WHERE id=? AND status='running'",
                       (status, json.dumps(result) if result is not None else None, error, now(), scan_id))

    def save_manifest(self, manifest: ScanManifest) -> None:
        m_dict = manifest.to_dict()
        with self.connect() as db:
            db.execute(
                """INSERT OR REPLACE INTO scan_manifests (
                    id, scan_id, input_hash, scanner_version, configuration_hash,
                    result_hash, data, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    manifest.manifest_id, manifest.scan_id, manifest.input_hash,
                    manifest.scanner_version, manifest.configuration_hash,
                    manifest.result_hash, json.dumps(m_dict), manifest.timestamp
                ),
            )

    def get_manifest(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self.connect() as db:
            row = db.execute("SELECT data FROM scan_manifests WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row["data"]) if row else None

    def get(self, scan_id, project):
        with self.connect() as db:
            row = db.execute('SELECT * FROM scans WHERE id=? AND project=?', (scan_id, project)).fetchone()
        if not row:
            return None
        value = dict(row)
        value.pop('payload', None)
        value['result'] = json.loads(value['result']) if value['result'] else None
        value['engine_version'] = '4.0.0'
        return value

    def list(self, project, status=None):
        with self.connect() as db:
            if status:
                ids = db.execute('SELECT id FROM scans WHERE project=? AND status=? ORDER BY created_at DESC LIMIT 200', (project, status)).fetchall()
            else:
                ids = db.execute('SELECT id FROM scans WHERE project=? ORDER BY created_at DESC LIMIT 200', (project,)).fetchall()
        return [self.get(row['id'], project) for row in ids]

    def get_payload(self, scan_id, project):
        with self.connect() as db:
            row = db.execute('SELECT payload FROM scans WHERE id=? AND project=?', (scan_id, project)).fetchone()
        return json.loads(row['payload']) if row and row['payload'] else None

    def cancel(self, scan_id, project):
        with self.connect() as db:
            db.execute("UPDATE scans SET status='cancelled', finished_at=? WHERE id=? AND project=? AND status IN ('queued','running')", (now(), scan_id, project))
        return self.get(scan_id, project)

    def save_plan(self, project, result):
        value = dict(result, id=str(uuid.uuid4()), project=project)
        with self.connect() as db:
            db.execute('INSERT INTO migration_plans VALUES (?,?,?,?)',
                       (value['id'], project, value['created_at'], json.dumps(value)))
        return value

    def get_plan(self, plan_id, project):
        with self.connect() as db:
            row = db.execute('SELECT result FROM migration_plans WHERE id=? AND project=?', (plan_id, project)).fetchone()
        return json.loads(row['result']) if row else None

    def list_plans(self, project):
        with self.connect() as db:
            rows = db.execute('SELECT id, created_at, result FROM migration_plans WHERE project=? ORDER BY created_at DESC LIMIT 100', (project,)).fetchall()
        return [{'id': r['id'], 'created_at': r['created_at'], 'target': json.loads(r['result'])['target']} for r in rows]

    # Graph & Evidence Query Helpers
    def get_assets(self, project: str, scan_id: Optional[str] = None) -> List[Dict[str, Any]]:
        query = "SELECT * FROM crypto_assets WHERE project = ?"
        params: List[Any] = [project]
        if scan_id:
            query += " AND scan_id = ?"
            params.append(scan_id)
        query += " ORDER BY created_at DESC"
        with self.connect() as db:
            rows = db.execute(query, params).fetchall()
        return [CryptoAsset.from_row(r).to_dict() for r in rows]

    def get_asset(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        asset = self.graph.get_asset(asset_id, project)
        return asset.to_dict() if asset else None

    def get_asset_evidence(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_asset_evidence(asset_id)

    def get_scan_evidence(self, scan_id: str, project: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.graph.get_scan_evidence(scan_id, project)

    def get_asset_relationships(self, asset_id: str, project: Optional[str] = None) -> Dict[str, Any]:
        return self.graph.get_neighbors(asset_id, direction="both")

    def get_blast_radius(self, node_id: str) -> Dict[str, Any]:
        return self.graph.get_blast_radius(node_id)

    def get_graph(self, project: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
        return self.graph.export_graph_for_ui(project, scan_id)

    # P2.1 Intelligence Query Helpers
    def get_risk_assessment(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_risk_assessment(asset_id)

    def save_risk_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        return self.graph.save_risk_assessment(assessment, engine_version=engine_version)

    def get_pqc_readiness(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_pqc_readiness(asset_id)

    def save_pqc_readiness(self, assessment: Any) -> str:
        return self.graph.save_pqc_readiness(assessment)

    def get_hndl_assessment(self, asset_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_hndl_assessment(asset_id)

    def save_hndl_assessment(self, assessment: Any) -> None:
        self.graph.save_hndl_assessment(assessment)

    def get_asset_intelligence(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_asset_intelligence(asset_id, project)

    def get_why_risk(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_why_risk(asset_id, project)

    # P2.2 Agility Intelligence Query Helpers
    def get_agility_assessment(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_agility_assessment(asset_id, scan_id)

    def get_all_agility_assessments(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_all_agility_assessments(asset_id)

    def save_agility_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        return self.graph.save_agility_assessment(assessment, engine_version=engine_version)

    def get_change_surface(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_change_surface(asset_id, scan_id)

    def save_change_surface(self, surface: Any) -> str:
        return self.graph.save_change_surface(surface)

    def get_why_agility(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_why_agility(asset_id, project)

    # P2.3 Blast Radius Intelligence Query Helpers
    def get_blast_radius_assessment(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_blast_radius_assessment(asset_id, scan_id)

    def get_all_blast_radius_assessments(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_all_blast_radius_assessments(asset_id)

    def save_blast_radius_assessment(self, assessment: Any, engine_version: str = "4.0.0") -> str:
        return self.graph.save_blast_radius_assessment(assessment, engine_version=engine_version)

    def get_why_blast_radius(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_why_blast_radius(asset_id, project)

    # P3 Migration Intelligence & Verification Query Helpers
    def get_pqc_migration_plan(self, asset_id: str, scan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_pqc_migration_plan(asset_id, scan_id)

    def get_pqc_migration_plan_by_id(self, plan_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_pqc_migration_plan_by_id(plan_id)

    def get_all_pqc_migration_plans(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_all_pqc_migration_plans(asset_id)

    def save_pqc_migration_plan(self, plan: Any) -> str:
        return self.graph.save_pqc_migration_plan(plan)

    def get_migration_verification(self, asset_id: str, plan_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_migration_verification(asset_id, plan_id)

    def get_migration_verification_by_id(self, verification_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_migration_verification_by_id(verification_id)

    def get_all_migration_verifications(self, asset_id: str) -> List[Dict[str, Any]]:
        return self.graph.get_all_migration_verifications(asset_id)

    def save_migration_verification(self, verification: Any) -> str:
        return self.graph.save_migration_verification(verification)

    def get_why_migration(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_why_migration(asset_id, project)

    # P5 Temporal Intelligence & Continuous Posture Query Helpers
    def save_temporal_comparison(self, comparison: Any) -> str:
        return self.graph.save_temporal_comparison(comparison)

    def get_temporal_comparison(self, project: str, base_scan_id: str, target_scan_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_temporal_comparison(project, base_scan_id, target_scan_id)

    def get_temporal_comparison_by_id(self, comparison_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_temporal_comparison_by_id(comparison_id)

    def save_evidence_timeline(self, timeline: Any) -> str:
        return self.graph.save_evidence_timeline(timeline)

    def get_evidence_timeline(self, asset_id: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_evidence_timeline(asset_id, project)

    def get_evidence_timeline_by_key(self, asset_key: str, project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_evidence_timeline_by_key(asset_key, project)

    def save_posture_assessment(self, assessment: Any) -> str:
        return self.graph.save_posture_assessment(assessment)

    def get_posture_assessment(self, scan_id: str, project: Optional[str] = None, asset_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        return self.graph.get_posture_assessment(scan_id, project, asset_id)

    def get_posture_assessment_by_id(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_posture_assessment_by_id(assessment_id)

    def get_posture_history(self, asset_id: Optional[str] = None, project: Optional[str] = None) -> List[Dict[str, Any]]:
        return self.graph.get_posture_history(asset_id, project)

    def save_posture_change(self, change: Any) -> str:
        return self.graph.save_posture_change(change)

    def get_posture_change(self, base_assessment_id: str, target_assessment_id: str) -> Optional[Dict[str, Any]]:
        return self.graph.get_posture_change(base_assessment_id, target_assessment_id)

    def close(self):
        self.pool.shutdown(wait=True)
