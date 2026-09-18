from contextlib import asynccontextmanager
from datetime import date
from fastapi.encoders import jsonable_encoder
import base64
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Literal, Optional

_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

try:
    import yaml
except ImportError:
    import json

    class _YamlCompat:
        @staticmethod
        def safe_load(stream):
            text = stream.read() if hasattr(stream, "read") else stream
            if hasattr(stream, "name"):
                try:
                    json_path = Path(stream.name).with_suffix(".json")
                    if json_path.exists():
                        with open(json_path, "r", encoding="utf-8") as jf:
                            return json.load(jf)
                except Exception:
                    pass
            try:
                return json.loads(text)
            except Exception:
                return {}

    import types
    _compat_mod = types.ModuleType("yaml")
    _compat_mod.safe_load = _YamlCompat.safe_load
    sys.modules["yaml"] = _compat_mod

from fastapi import FastAPI, APIRouter, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator
from engine.scan_store import ScanStore
from engine.source_scan import scan_sources, LANGUAGES
from engine.binary_deep import scan_upload, MAX_BYTES
from engine.website_inspector import scan_website
from engine.migration_planner import build_plan
from engine.cbom_generator import generate_cyclonedx_cbom
from engine.agility_engine import calculate_crypto_agility
from engine.migration_simulator import simulate_pqc_migration_roadmap
from engine.quantum_risk import calculate_mosca_risk
from engine.evidence_model import (
    EvidenceRecord,
    normalize_source_finding,
    normalize_binary_detection,
    normalize_network_scan
)
from engine.correlator import CrossSurfaceCorrelator
from engine.verifier import ClosedLoopVerifier
from engine.knowledge_graph import CryptoKnowledgeGraph
from engine.standards_mapping import get_all_standards
from engine.pcap_engine import PcapEngine
from engine.runtime_tracer import RuntimeTracer
from engine.ebpf_tracer import EbpfTracer
from engine.custom_crypto_detector import CustomCryptoDetector
from engine.patch_engine import AutoPatchEngine
from engine.quantum_estimator import QuantumResourceEstimator
from engine.binary_classifier import BinaryMLClassifier
from engine.demo_flow import SihDemoRunner


@asynccontextmanager
async def lifespan(app):
    app.state.store = ScanStore()
    yield
    app.state.store.close()


app = FastAPI(title='ECDAT API', version='3.0.0', lifespan=lifespan)
origins = [x.strip() for x in os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',') if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=['GET', 'POST'], allow_headers=['Content-Type', 'Authorization'])


@app.middleware('http')
async def access_and_size(request: Request, call_next):
    from fastapi.responses import JSONResponse
    token = os.getenv('ECDAT_API_TOKEN', '')
    if request.method != 'OPTIONS' and request.url.path not in ('/', '/health', '/api/health') and token:
        if not secrets.compare_digest(request.headers.get('authorization', ''), 'Bearer ' + token):
            return JSONResponse({'detail': 'Unauthorized'}, status_code=401)
    # Bound both declared and streamed request bodies, before JSON/multipart parsing.
    if request.method == 'POST':
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 18 * 1024 * 1024:
                return JSONResponse({'detail': 'Request exceeds 18 MiB'}, status_code=413)
        request._body = bytes(body)
    return await call_next(request)


router = APIRouter()
Project = Query(default='default', min_length=1, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')


class NetworkRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


class SourceFile(BaseModel):
    path: str = Field(min_length=1, max_length=300)
    content: str = Field(max_length=500_000)
    language: str | None = None

    @model_validator(mode='after')
    def valid_file(self):
        if self.path.startswith('/') or '..' in self.path.replace('\\', '/').split('/'):
            raise ValueError('Use a relative file path without parent traversal')
        if self.language is not None and self.language not in LANGUAGES:
            raise ValueError('Unsupported language')
        return self


class CodeRequest(BaseModel):
    source_code: str = Field(min_length=1, max_length=500_000)
    language: Literal['python', 'java', 'c_cpp', 'golang', 'javascript'] = 'python'


class SourcesRequest(BaseModel):
    files: list[SourceFile] = Field(min_length=1, max_length=100)

    @model_validator(mode='after')
    def valid_total(self):
        if sum(len(f.content.encode()) for f in self.files) > MAX_BYTES:
            raise ValueError('Source bundle exceeds 8 MiB')
        if len({f.path for f in self.files}) != len(self.files):
            raise ValueError('Duplicate source paths')
        return self


class BinaryRequest(BaseModel):
    raw_hex: str = Field(min_length=2, max_length=MAX_BYTES * 2)
    file_name: str = Field(default='upload.bin', max_length=300)


def enqueue(request, project, kind, payload, worker):
    try:
        return request.app.state.store.submit(project, kind, payload, worker)
    except ValueError as exc:
        raise HTTPException(429, str(exc)) from exc


@router.get('/health')
def health():
    return {'status': 'ok', 'version': '3.0.0'}


@router.post('/scan/network', status_code=202)
def network(req: NetworkRequest, request: Request, project: str = Project):
    return enqueue(request, project, 'network', req.model_dump(), lambda p: scan_website(p['target'], p['port']))


@router.post('/scan/code', status_code=202)
def code(req: CodeRequest, request: Request, project: str = Project):
    files = [{'path': 'snippet.' + {'python': 'py', 'java': 'java', 'c_cpp': 'cpp', 'golang': 'go', 'javascript': 'js'}[req.language], 'content': req.source_code, 'language': req.language}]
    return enqueue(request, project, 'code', {'files': files}, lambda p: scan_sources(p['files']))


@router.post('/scan/sources', status_code=202)
def sources(req: SourcesRequest, request: Request, project: str = Project):
    return enqueue(request, project, 'code', req.model_dump(), lambda p: scan_sources(p['files']))


def binary_worker(payload):
    return scan_upload(base64.b64decode(payload['bytes']), payload['file_name'])


@router.post('/scan/binary', status_code=202)
def binary(req: BinaryRequest, request: Request, project: str = Project):
    try:
        raw = bytes.fromhex(req.raw_hex)
        if not raw or len(raw) > MAX_BYTES:
            raise ValueError()
    except ValueError:
        raise HTTPException(422, 'Supply valid hex representing 1 byte to 8 MiB')
    return enqueue(request, project, 'binary', {'bytes': base64.b64encode(raw).decode(), 'file_name': req.file_name}, binary_worker)


@router.post('/scan/binary/upload', status_code=202)
async def upload(request: Request, file: UploadFile = File(...), project: str = Project):
    raw = await file.read(MAX_BYTES + 1)
    await file.close()
    if not raw or len(raw) > MAX_BYTES:
        raise HTTPException(413, 'Upload must contain 1 byte to 8 MiB')
    return enqueue(request, project, 'binary', {'bytes': base64.b64encode(raw).decode(), 'file_name': (file.filename or 'upload.bin')[:300]}, binary_worker)


@router.get('/scans')
def scans(request: Request, project: str = Project):
    return request.app.state.store.list(project)


@router.get('/scans/{scan_id}')
def scan(scan_id: str, request: Request, project: str = Project):
    result = request.app.state.store.get(scan_id, project)
    if result is None:
        raise HTTPException(404, 'Scan not found')
    return result


@router.post('/scans/{scan_id}/cancel')
def cancel(scan_id: str, request: Request, project: str = Project):
    result = request.app.state.store.cancel(scan_id, project)
    if result is None:
        raise HTTPException(404, 'Scan not found')
    return result


@router.get('/scans/{scan_id}/evidence')
def scan_evidence(scan_id: str, request: Request, project: str = Project):
    record = request.app.state.store.get(scan_id, project)
    if record is None:
        raise HTTPException(404, 'Scan not found')
    return request.app.state.store.get_scan_evidence(scan_id, project)


@router.get('/scans/{scan_id}/manifest')
def scan_manifest(scan_id: str, request: Request, project: str = Project):
    record = request.app.state.store.get(scan_id, project)
    if record is None:
        raise HTTPException(404, 'Scan not found')
    manifest = request.app.state.store.get_manifest(scan_id)
    if manifest is None:
        raise HTTPException(404, 'Manifest not found')
    return manifest


@router.get('/scans/{scan_id}/graph')
def scan_graph(scan_id: str, request: Request, project: str = Project):
    record = request.app.state.store.get(scan_id, project)
    if record is None:
        raise HTTPException(404, 'Scan not found')
    return request.app.state.store.get_graph(project, scan_id)


@router.get('/assets')
def list_assets(request: Request, project: str = Project, scan_id: Optional[str] = None):
    return request.app.state.store.get_assets(project, scan_id)


@router.get('/assets/{asset_id}')
def asset_detail(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    return asset


@router.get('/assets/{asset_id}/evidence')
def asset_evidence(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    return request.app.state.store.get_asset_evidence(asset_id)


@router.get('/assets/{asset_id}/relationships')
def asset_relationships(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    return request.app.state.store.get_asset_relationships(asset_id, project)


@router.get('/assets/{asset_id}/blast-radius')
def asset_blast_radius(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    assessment = request.app.state.store.get_blast_radius_assessment(asset_id)
    if assessment is None:
        from engine.blast_radius.blast_radius_pipeline import evaluate_blast_radius
        evidence = request.app.state.store.get_asset_evidence(asset_id)
        eval_res = evaluate_blast_radius(asset, graph_service=request.app.state.store, evidence_items=evidence)
        request.app.state.store.save_blast_radius_assessment(eval_res)
        assessment = eval_res.to_dict()
    # Ensure 100% backward compatibility with P0 contract (target_node_id, total_impacted_count, impacted_assets)
    if "target_node_id" not in assessment:
        assessment["target_node_id"] = asset_id
    if "impacted_assets" not in assessment:
        assessment["impacted_assets"] = assessment.get("affected_assets", [])
    if "total_impacted_count" not in assessment:
        assessment["total_impacted_count"] = len(assessment.get("impacted_assets", []))
    return assessment


@router.get('/assets/{asset_id}/blast-radius/why')
def asset_blast_radius_why(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    why = request.app.state.store.get_why_blast_radius(asset_id, project)
    if why is None:
        raise HTTPException(404, 'Blast radius explainability report not found')
    return why


@router.get('/assets/{asset_id}/blast-radius/paths')
def asset_blast_radius_paths(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    assessment = request.app.state.store.get_blast_radius_assessment(asset_id)
    if assessment is None:
        from engine.blast_radius.blast_radius_pipeline import evaluate_blast_radius
        evidence = request.app.state.store.get_asset_evidence(asset_id)
        eval_res = evaluate_blast_radius(asset, graph_service=request.app.state.store, evidence_items=evidence)
        request.app.state.store.save_blast_radius_assessment(eval_res)
        assessment = eval_res.to_dict()
    return {
        "asset_id": asset_id,
        "direct_dependents": assessment.get("direct_dependents", []),
        "transitive_dependents": assessment.get("transitive_dependents", []),
        "paths": assessment.get("dependency_paths", []),
        "total_paths": len(assessment.get("dependency_paths", [])),
    }


@router.get('/assets/{asset_id}/blast-radius/criticality')
def asset_blast_radius_criticality(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    assessment = request.app.state.store.get_blast_radius_assessment(asset_id)
    if assessment is None:
        from engine.blast_radius.blast_radius_pipeline import evaluate_blast_radius
        evidence = request.app.state.store.get_asset_evidence(asset_id)
        eval_res = evaluate_blast_radius(asset, graph_service=request.app.state.store, evidence_items=evidence)
        request.app.state.store.save_blast_radius_assessment(eval_res)
        assessment = eval_res.to_dict()
    return {
        "asset_id": asset_id,
        "criticality": assessment.get("criticality", "UNKNOWN"),
        "reasons": [r for r in assessment.get("reason_chain", []) if r.get("step") == "ARCHITECTURAL_CRITICALITY_EVALUATION"],
    }


@router.get('/assets/{asset_id}/migration')
def asset_migration(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    plan = request.app.state.store.get_pqc_migration_plan(asset_id)
    if plan is None:
        from engine.migration.migration_pipeline import generate_migration_plan
        risk = request.app.state.store.get_risk_assessment(asset_id)
        agility = request.app.state.store.get_agility_assessment(asset_id)
        pqc = request.app.state.store.get_pqc_readiness(asset_id)
        blast = request.app.state.store.get_blast_radius_assessment(asset_id)
        evidence = request.app.state.store.get_asset_evidence(asset_id)
        plan_res = generate_migration_plan(
            asset=asset,
            risk_assessment=risk,
            agility_assessment=agility,
            pqc_readiness=pqc,
            blast_radius=blast,
            evidence_items=evidence,
        )
        request.app.state.store.save_pqc_migration_plan(plan_res)
        plan = plan_res.to_dict()
    return plan


@router.get('/assets/{asset_id}/migration/why')
def asset_migration_why(asset_id: str, request: Request, project: str = Project):
    why = request.app.state.store.get_why_migration(asset_id, project)
    if why is None:
        raise HTTPException(404, 'Asset or migration plan not found')
    return why


@router.get('/assets/{asset_id}/migration/verification')
def asset_migration_verification(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    ver = request.app.state.store.get_migration_verification(asset_id)
    if ver is None:
        raise HTTPException(404, 'Migration verification not found')
    return ver


@router.get('/assets/{asset_id}/risk')
def asset_risk(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    risk = request.app.state.store.get_risk_assessment(asset_id)
    if risk is None:
        intel = request.app.state.store.get_asset_intelligence(asset_id, project)
        risk = intel.get('risk') if intel else None
    if risk is None:
        raise HTTPException(404, 'Risk assessment not found')
    return risk


@router.get('/assets/{asset_id}/pqc-readiness')
def asset_pqc_readiness(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    pqc = request.app.state.store.get_pqc_readiness(asset_id)
    if pqc is None:
        intel = request.app.state.store.get_asset_intelligence(asset_id, project)
        pqc = intel.get('pqc_readiness') if intel else None
    if pqc is None:
        raise HTTPException(404, 'PQC readiness assessment not found')
    return pqc


@router.get('/assets/{asset_id}/intelligence')
def asset_intelligence(asset_id: str, request: Request, project: str = Project):
    intel = request.app.state.store.get_asset_intelligence(asset_id, project)
    if intel is None:
        raise HTTPException(404, 'Asset or intelligence not found')
    return intel


@router.get('/assets/{asset_id}/why-risk')
def asset_why_risk(asset_id: str, request: Request, project: str = Project):
    why = request.app.state.store.get_why_risk(asset_id, project)
    if why is None:
        raise HTTPException(404, 'Asset or explainability report not found')
    return why


@router.get('/assets/{asset_id}/agility')
def asset_agility(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    agility = request.app.state.store.get_agility_assessment(asset_id)
    if agility is None:
        from engine.agility.agility_pipeline import evaluate_agility
        evidence = request.app.state.store.get_asset_evidence(asset_id)
        blast = request.app.state.store.get_blast_radius(asset_id)
        eval_res = evaluate_agility(asset, evidence, graph_service=request.app.state.store, blast_radius=blast)
        request.app.state.store.save_agility_assessment(eval_res)
        agility = eval_res.to_dict()
    return agility


@router.get('/assets/{asset_id}/agility/why')
def asset_agility_why(asset_id: str, request: Request, project: str = Project):
    why = request.app.state.store.get_why_agility(asset_id, project)
    if why is None:
        raise HTTPException(404, 'Asset or agility explainability report not found')
    return why


@router.get('/assets/{asset_id}/change-surface')
def asset_change_surface(asset_id: str, request: Request, project: str = Project):
    asset = request.app.state.store.get_asset(asset_id, project)
    if asset is None:
        raise HTTPException(404, 'Asset not found')
    surface = request.app.state.store.get_change_surface(asset_id)
    if surface is None:
        from engine.agility.agility_pipeline import evaluate_agility
        evidence = request.app.state.store.get_asset_evidence(asset_id)
        blast = request.app.state.store.get_blast_radius(asset_id)
        eval_res = evaluate_agility(asset, evidence, graph_service=request.app.state.store, blast_radius=blast)
        request.app.state.store.save_agility_assessment(eval_res)
        surface = eval_res.change_surface.to_dict() if eval_res.change_surface else None
    if surface is None:
        raise HTTPException(404, 'Change surface not found')
    return surface



class EvaluateIntelligenceRequest(BaseModel):
    asset: dict = Field(..., description="Asset dictionary with algorithm/name and optional parameters")
    evidence: list[dict] = Field(default_factory=list, description="P0 evidence records supporting asset")
    context: dict = Field(default_factory=dict, description="Environmental or architectural context")


@router.post('/intelligence/evaluate')
def evaluate_intelligence_endpoint(req: EvaluateIntelligenceRequest):
    from engine.intelligence.intelligence_pipeline import evaluate_asset
    assessment = evaluate_asset(req.asset, req.evidence, req.context)
    return assessment.to_dict()


class EvaluateBlastRadiusRequest(BaseModel):
    asset: dict = Field(..., description="Target asset dictionary with id/name/algorithm")
    evidence: list[dict] = Field(default_factory=list, description="Associated evidence items")
    context: dict = Field(default_factory=dict, description="Execution environment or architectural context")
    edges: list[dict] = Field(default_factory=list, description="Optional raw graph edges for in-memory traversal")
    nodes: list[dict] = Field(default_factory=list, description="Optional raw graph nodes for in-memory traversal")
    max_depth: int = Field(default=10, ge=1, le=50)
    max_paths: int = Field(default=100, ge=1, le=500)
    max_nodes: int = Field(default=500, ge=1, le=2000)
    max_edges: int = Field(default=1000, ge=1, le=5000)


@router.post('/blast-radius/evaluate')
def evaluate_blast_radius_endpoint(req: EvaluateBlastRadiusRequest, request: Request):
    from engine.blast_radius.blast_radius_pipeline import evaluate_blast_radius
    store = getattr(request.app.state, "store", None)
    assessment = evaluate_blast_radius(
        target_asset=req.asset,
        graph_service=store,
        evidence_items=req.evidence,
        context=req.context,
        raw_edges=req.edges,
        raw_nodes=req.nodes,
        max_depth=req.max_depth,
        max_paths=req.max_paths,
        max_nodes=req.max_nodes,
        max_edges=req.max_edges,
    )
    return assessment.to_dict()


class GenerateMigrationPlanRequest(BaseModel):
    asset: dict = Field(..., description="Target asset dictionary with id/name/algorithm")
    risk_assessment: Optional[dict] = Field(default=None, description="P2.1 Risk assessment")
    agility_assessment: Optional[dict] = Field(default=None, description="P2.2 Agility assessment")
    pqc_readiness: Optional[dict] = Field(default=None, description="P2.1 PQC readiness assessment")
    blast_radius: Optional[dict] = Field(default=None, description="P2.3 Blast radius assessment")
    evidence: list[dict] = Field(default_factory=list, description="Associated evidence records")
    overrides: Optional[dict] = Field(default=None, description="Optional target or priority overrides")


@router.post('/migration/plan')
def create_pqc_migration_plan(req: GenerateMigrationPlanRequest, request: Request):
    from engine.migration.migration_pipeline import generate_migration_plan
    store = getattr(request.app.state, "store", None)
    plan = generate_migration_plan(
        asset=req.asset,
        risk_assessment=req.risk_assessment,
        agility_assessment=req.agility_assessment,
        pqc_readiness=req.pqc_readiness,
        blast_radius=req.blast_radius,
        evidence_items=req.evidence,
        overrides=req.overrides,
    )
    if store and hasattr(store, "save_pqc_migration_plan"):
        store.save_pqc_migration_plan(plan)
    return plan.to_dict()


class VerifyMigrationRequest(BaseModel):
    plan: Optional[dict] = Field(default=None, description="Migration plan to verify")
    before_scan: Optional[dict] = Field(default=None, description="Pre-migration scan results and observations")
    after_scan: Optional[dict] = Field(default=None, description="Post-migration scan results and observations")
    asset_id: Optional[str] = Field(default=None, description="Target asset ID")
    evidence: list[dict] = Field(default_factory=list, description="Associated evidence records")


@router.post('/migration/verify')
def verify_migration_endpoint(req: VerifyMigrationRequest, request: Request):
    from engine.migration.migration_pipeline import execute_migration_verification
    from engine.migration.models import MigrationPlan
    store = getattr(request.app.state, "store", None)
    plan_obj = MigrationPlan.from_dict(req.plan) if req.plan else None
    ver = execute_migration_verification(
        plan=plan_obj,
        before_scan=req.before_scan,
        after_scan=req.after_scan,
        asset_id=req.asset_id,
        evidence_items=req.evidence,
    )
    if store and hasattr(store, "save_migration_verification"):
        store.save_migration_verification(ver)
    return ver.to_dict()



@router.get('/graph')
def project_graph(request: Request, project: str = Project):
    try:
        g = request.app.state.store.get_graph(project)
        if g and g.get('nodes'):
            return g
    except Exception:
        pass
    records = [r for r in request.app.state.store.list(project) if r['status'] == 'completed']
    if not records:
        return CryptoKnowledgeGraph().export_for_ui()
    kg = CryptoKnowledgeGraph.from_scans(records, app_name=project)
    return kg.export_for_ui()



@router.get('/overview')
def overview(request: Request, project: str = Project):
    records = [r for r in request.app.state.store.list(project) if r['status'] == 'completed']
    nodes, links, findings = [], [], []
    for record in records:
        result = record['result']
        evidence = result.get('findings', result.get('detections', []))
        if record['kind'] == 'network':
            evidence = [{'primitive': result.get('cipher_name', 'Unknown'), 'severity': 'LOW'}]
        elif record['kind'] == 'pcap':
            evidence = [{'primitive': s.get('selected_cipher') or s.get('cipher_suite', 'TLS Session'), 'severity': 'HIGH' if s.get('is_quantum_vulnerable') else 'LOW', 'file': f"{s.get('server_ip')}:{s.get('server_port', 443)}"} for s in result.get('sessions', [])]

        nodes.append({'id': record['id'], 'label': record['kind'] + ' ' + record['id'][:8], 'group': 'service', 'severity': 'low', 'blast_radius': []})
        for i, finding in enumerate(evidence):
            node_id = record['id'] + ':' + str(i)
            nodes.append({'id': node_id, 'label': finding['primitive'], 'group': 'algorithm', 'severity': finding.get('severity', 'LOW').lower(), 'blast_radius': [record['id']]})
            links.append({'source': record['id'], 'target': node_id, 'label': finding.get('file', 'TLS observation')})
            findings.append(finding)
    return {'kpis': {'total_findings': len(findings), 'critical': sum(f.get('severity') == 'CRITICAL' for f in findings),
                     'quantum_vulnerable_certs': 0, 'est_migration_effort': 'Not assessed'},
            'graph': {'nodes': nodes, 'links': links}, 'scan_count': len(records),
            'limitations': ['Quantum-vulnerable certificate count is not assessed. History limited to latest 200 scans.']}


class ExportRequest(BaseModel):
    scan_ids: list[str] = Field(min_length=1, max_length=200)
    target_name: str = Field(default='ECDAT Project', max_length=200)


@router.post('/export/cbom')
def export(req: ExportRequest, request: Request, project: str = Project):
    records = []
    for scan_id in dict.fromkeys(req.scan_ids):
        record = request.app.state.store.get(scan_id, project)
        if record is None or record['status'] != 'completed':
            raise HTTPException(422, 'Export requires completed scans from this project')
        records.append(record)
    return generate_cyclonedx_cbom(records, req.target_name)


class AgilityRequest(BaseModel):
    hardcoded_primitives_count: int = Field(default=0, ge=0)
    abstracted_primitives_count: int = Field(default=0, ge=0)
    has_provider_abstraction: bool = False
    has_pqc_hybrid_support: bool = False
    automated_cert_rotation: bool = False
    uses_config_driven_crypto: bool = False


@router.post('/agility/evaluate')
def agility(req: AgilityRequest):
    return calculate_crypto_agility(**req.model_dump())


class EvaluateAgilityV2Request(BaseModel):
    asset: dict = Field(..., description="Asset dictionary with algorithm/name and optional parameters")
    evidence: list[dict] = Field(default_factory=list, description="P0/P1 evidence records supporting asset")
    context: dict = Field(default_factory=dict, description="Environmental or architectural context")


@router.post('/agility/evaluate-v2')
def evaluate_agility_v2_endpoint(req: EvaluateAgilityV2Request, request: Request):
    from engine.agility.agility_pipeline import evaluate_agility
    store = getattr(request.app.state, "store", None)
    assessment = evaluate_agility(req.asset, req.evidence, req.context, graph_service=store)
    return assessment.to_dict()



class MigrationRequest(BaseModel):
    x_shelf_life: int = Field(default=10, ge=0, le=100)
    y_migration_time: int = Field(default=4, ge=0, le=100)
    z_crqc_horizon: int = Field(default=8, ge=0, le=100)
    critical_findings_count: int = Field(default=0, ge=0)
    qv_certs_count: int = Field(default=0, ge=0)


@router.post('/migration/simulate')
def migration(req: MigrationRequest):
    return simulate_pqc_migration_roadmap(**req.model_dump())


class TrafficInput(BaseModel):
    source: str = Field(min_length=1, max_length=200)
    start_date: date
    end_date: date
    total_requests: int = Field(ge=0, le=10**15)
    total_gb: float | None = Field(default=None, ge=0, le=10**12, allow_inf_nan=False)

    @model_validator(mode='after')
    def valid_period(self):
        if self.end_date < self.start_date or self.end_date > date.today():
            raise ValueError('Use a completed, chronological observation period')
        if (self.end_date - self.start_date).days > 366:
            raise ValueError('Traffic period must be at most 367 days')
        if not self.source.strip():
            raise ValueError('Name the analytics source')
        return self


class WebsitePlanRequest(BaseModel):
    scan_ids: list[str] = Field(min_length=1, max_length=100)
    current_host: str | None = Field(default=None, max_length=200)
    target_host: str | None = Field(default=None, max_length=200)
    stack: str | None = Field(default=None, max_length=200)
    database: Literal['unknown', 'none', 'postgresql', 'mysql', 'mongodb', 'other'] = 'unknown'
    application_count: int = Field(default=1, ge=1, le=100)
    data_gb: float | None = Field(default=None, ge=0, le=10**9, allow_inf_nan=False)
    transfer_mbps: float | None = Field(default=None, gt=0, le=10**7, allow_inf_nan=False)
    traffic: TrafficInput | None = None


@router.post('/migration/plans', status_code=201)
def create_website_plan(req: WebsitePlanRequest, request: Request, project: str = Project):
    records = [request.app.state.store.get(i, project) for i in dict.fromkeys(req.scan_ids)]
    if any(r is None or r['status'] != 'completed' for r in records):
        raise HTTPException(422, 'Select completed scans from this project')
    if sum(r['kind'] == 'network' for r in records) != 1:
        raise HTTPException(422, 'Select exactly one website/network scan and any related source or binary scans')
    inputs = req.model_dump(exclude={'scan_ids'})
    for key in ('current_host', 'target_host', 'stack'):
        inputs[key] = (inputs.get(key) or '').strip() or None
    result = build_plan(records, inputs)
    return request.app.state.store.save_plan(project, jsonable_encoder(result))


@router.get('/migration/plans')
def website_plans(request: Request, project: str = Project):
    return request.app.state.store.list_plans(project)


@router.get('/migration/plans/{plan_id}')
def website_plan(plan_id: str, request: Request, project: str = Project):
    result = request.app.state.store.get_plan(plan_id, project)
    if result is None:
        raise HTTPException(404, 'Plan not found')
    return result


class MoscaRequest(BaseModel):
    x: int = Field(default=10, ge=0, le=100)
    y: int = Field(default=4, ge=0, le=100)
    z: int = Field(default=8, ge=0, le=100)


@router.post('/risk/mosca')
def mosca(req: MoscaRequest):
    return calculate_mosca_risk(req.x, req.y, req.z)


# =========================================================================
# P4.1 Knowledge & P4.2 Research Evaluation Endpoints
# =========================================================================


@router.get('/knowledge/version')
def get_knowledge_version():
    from engine.knowledge_version import load_knowledge_version
    kb = load_knowledge_version()
    return {
        "knowledge_base_id": kb.knowledge_base_id,
        "knowledge_base_version": kb.version,
        "schema_version": kb.schema_version,
        "engine_version": kb.engine_version,
        "knowledge_hash": kb.knowledge_hash,
        "provenance": kb.provenance,
        "compatibility_notes": kb.compatibility_notes,
    }


@router.get('/knowledge/summary')
def get_knowledge_summary():
    from engine.knowledge_version import load_knowledge_version
    kb = load_knowledge_version()
    return {
        "knowledge_base_version": kb.version,
        "knowledge_hash": kb.knowledge_hash,
        "rule_count": kb.rule_count,
        "algorithm_count": kb.algorithm_count,
        "migration_mapping_count": kb.migration_mapping_count,
        "sources": kb.sources,
    }


@router.get('/evaluation/latest')
def get_evaluation_latest():
    from pathlib import Path
    import json
    res_path = Path(__file__).resolve().parent / "evaluation" / "results" / "evaluation_result.json"
    if not res_path.exists():
        from evaluation import run_benchmark
        result = run_benchmark()
        return result.to_dict()
    with open(res_path, "r", encoding="utf-8") as f:
        return json.load(f)


@router.get('/evaluation/summary')
def get_evaluation_summary():
    from pathlib import Path
    import json
    res_path = Path(__file__).resolve().parent / "evaluation" / "results" / "evaluation_result.json"
    if not res_path.exists():
        from evaluation import run_benchmark
        result = run_benchmark()
        return {
            "overall_metrics": result.overall_metrics,
            "dataset_version": result.dataset_version,
            "dataset_hash": result.dataset_hash,
            "result_hash": result.result_hash,
        }
    with open(res_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        "overall_metrics": data.get("overall_metrics", {}),
        "dataset_version": data.get("dataset_version", ""),
        "dataset_hash": data.get("dataset_hash", ""),
        "result_hash": data.get("result_hash", ""),
    }


@router.get('/evaluation/modalities')
def get_evaluation_modalities():
    from pathlib import Path
    import json
    res_path = Path(__file__).resolve().parent / "evaluation" / "results" / "evaluation_result.json"
    if not res_path.exists():
        from evaluation import run_benchmark
        result = run_benchmark()
        return {
            "modality_metrics": result.modality_metrics,
            "result_hash": result.result_hash,
        }
    with open(res_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        "modality_metrics": data.get("modality_metrics", {}),
        "result_hash": data.get("result_hash", ""),
    }


# =========================================================
# P5: Temporal Crypto Intelligence & Continuous Posture APIs
# =========================================================

class TemporalCompareRequest(BaseModel):
    base_scan_id: str = Field(min_length=1, max_length=100)
    target_scan_id: str = Field(min_length=1, max_length=100)
    project: str = Field(default='default', min_length=1, max_length=64)


class PostureEvaluateRequest(BaseModel):
    scan_id: str = Field(default='scan-1', min_length=1, max_length=100)
    base_scan_id: Optional[str] = Field(default=None, max_length=100)
    target_scan_id: Optional[str] = Field(default=None, max_length=100)
    asset_id: Optional[str] = Field(default=None, max_length=100)
    project: str = Field(default='default', min_length=1, max_length=64)


@router.get('/assets/{asset_id}/timeline')
def get_asset_timeline(asset_id: str, request: Request, project: str = Project):
    store = request.app.state.store
    from engine.temporal.pipeline import TemporalPipeline
    pipeline = TemporalPipeline(store)
    timeline = pipeline.get_asset_timeline(project, asset_id)
    if not timeline:
        raise HTTPException(404, f"Timeline for asset {asset_id} not found")
    return timeline


@router.get('/assets/{asset_id}/changes')
def get_asset_changes(asset_id: str, request: Request, project: str = Project):
    store = request.app.state.store
    from engine.temporal.pipeline import TemporalPipeline
    pipeline = TemporalPipeline(store)
    timeline = pipeline.get_asset_timeline(project, asset_id)
    changes = [e for e in timeline.get("events", []) if e.get("event_type") in ("ALGORITHM_CHANGED", "RISK_CHANGED", "SUPERSEDED", "STALE", "REMOVED")]
    return {
        "asset_id": asset_id,
        "project": project,
        "change_events": changes,
        "timeline_summary": timeline.get("current_status"),
    }


@router.get('/assets/{asset_id}/posture')
def get_asset_posture(asset_id: str, request: Request, project: str = Project):
    store = request.app.state.store
    from engine.posture.pipeline import PosturePipeline
    pipeline = PosturePipeline(store)
    asset = store.graph.get_asset(asset_id, project)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} not found")
    scan_id = asset.scan_id or "default"
    posture = pipeline.evaluate_scan_posture(project, scan_id, asset_id=asset_id)
    return posture


@router.get('/assets/{asset_id}/posture/history')
def get_asset_posture_history(asset_id: str, request: Request, project: str = Project):
    store = request.app.state.store
    from engine.posture.pipeline import PosturePipeline
    pipeline = PosturePipeline(store)
    history = pipeline.get_asset_posture_history(project, asset_id)
    return {
        "asset_id": asset_id,
        "project": project,
        "history_count": len(history),
        "history": history,
    }


@router.get('/assets/{asset_id}/temporal-risk')
def get_asset_temporal_risk(asset_id: str, request: Request, project: str = Project):
    store = request.app.state.store
    from engine.temporal.temporal_risk import evaluate_temporal_risk
    asset = store.graph.get_asset(asset_id, project)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} not found")
    risk = store.graph.get_risk_assessment(asset_id)
    risk_change, expl = evaluate_temporal_risk(None, risk)
    return {
        "asset_id": asset_id,
        "current_risk": risk,
        "temporal_risk_change": risk_change.value,
        "explanation": expl,
    }


@router.get('/assets/{asset_id}/temporal-pqc')
def get_asset_temporal_pqc(asset_id: str, request: Request, project: str = Project):
    store = request.app.state.store
    from engine.temporal.temporal_pqc import evaluate_temporal_pqc
    asset = store.graph.get_asset(asset_id, project)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} not found")
    pqc = store.graph.get_pqc_readiness(asset_id)
    asset_dict = asset.to_dict() if hasattr(asset, "to_dict") else dict(asset)
    pqc_change, expl = evaluate_temporal_pqc(None, pqc, None, asset_dict)
    return {
        "asset_id": asset_id,
        "current_pqc": pqc,
        "temporal_pqc_change": pqc_change.value,
        "explanation": expl,
    }


@router.get('/assets/{asset_id}/temporal-agility')
def get_asset_temporal_agility(asset_id: str, request: Request, project: str = Project):
    store = request.app.state.store
    from engine.temporal.temporal_agility import evaluate_temporal_agility
    asset = store.graph.get_asset(asset_id, project)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} not found")
    agility = store.graph.get_agility_assessment(asset_id, asset.scan_id)
    ag_change, expl = evaluate_temporal_agility(None, agility)
    return {
        "asset_id": asset_id,
        "current_agility": agility,
        "temporal_agility_change": ag_change.value,
        "explanation": expl,
    }


@router.get('/assets/{asset_id}/temporal-migration')
def get_asset_temporal_migration(asset_id: str, request: Request, project: str = Project):
    store = request.app.state.store
    from engine.temporal.temporal_migration import evaluate_temporal_migration
    asset = store.graph.get_asset(asset_id, project)
    if not asset:
        raise HTTPException(404, f"Asset {asset_id} not found")
    plan = store.graph.get_pqc_migration_plan(asset_id)
    ver = store.graph.get_migration_verification(asset_id)
    mig_change, expl = evaluate_temporal_migration(plan, ver)
    return {
        "asset_id": asset_id,
        "migration_plan": plan,
        "migration_verification": ver,
        "temporal_migration_change": mig_change.value,
        "explanation": expl,
    }


@router.post('/temporal/compare')
def post_temporal_compare(req: TemporalCompareRequest, request: Request):
    store = request.app.state.store
    from engine.temporal.pipeline import TemporalPipeline
    pipeline = TemporalPipeline(store)
    result = pipeline.run_comparison(
        project=req.project,
        base_scan_id=req.base_scan_id,
        target_scan_id=req.target_scan_id,
    )
    return result


@router.post('/posture/evaluate')
def post_posture_evaluate(req: PostureEvaluateRequest, request: Request):
    store = request.app.state.store
    from engine.posture.pipeline import PosturePipeline
    pipeline = PosturePipeline(store)
    if req.base_scan_id and req.target_scan_id:
        change = pipeline.evaluate_posture_change_between_scans(
            project=req.project,
            base_scan_id=req.base_scan_id,
            target_scan_id=req.target_scan_id,
            asset_id=req.asset_id,
        )
        return change
    else:
        assessment = pipeline.evaluate_scan_posture(
            project=req.project,
            scan_id=req.scan_id,
            asset_id=req.asset_id,
        )
        return assessment


@router.get('/evidence/records')
def get_evidence_records(request: Request, project: str = Project):
    records = [r for r in request.app.state.store.list(project) if r['status'] == 'completed']
    correlator = CrossSurfaceCorrelator()
    correlator.ingest_scan_results(records)
    return [e.model_dump() for e in correlator.evidence]


@router.get('/correlate')
def get_correlated_topology(request: Request, project: str = Project):
    records = [r for r in request.app.state.store.list(project) if r['status'] == 'completed']
    correlator = CrossSurfaceCorrelator()
    correlator.ingest_scan_results(records)
    return correlator.correlate(default_app_name=project).model_dump()


class VerifyRequest(BaseModel):
    baseline_scan_ids: list[str] = Field(min_length=1)
    post_migration_scan_ids: list[str] = Field(min_length=1)
    target_weaknesses: list[str] | None = None


@router.post('/verify')
def verify_migration(req: VerifyRequest, request: Request, project: str = Project):
    b_records = [request.app.state.store.get(sid, project) for sid in dict.fromkeys(req.baseline_scan_ids)]
    p_records = [request.app.state.store.get(sid, project) for sid in dict.fromkeys(req.post_migration_scan_ids)]
    if any(r is None or r['status'] != 'completed' for r in b_records + p_records):
        raise HTTPException(422, 'Verification requires valid completed scans from this project')

    c_base = CrossSurfaceCorrelator()
    c_base.ingest_scan_results(b_records)
    c_post = CrossSurfaceCorrelator()
    c_post.ingest_scan_results(p_records)

    report = ClosedLoopVerifier.verify(
        baseline_records=c_base.evidence,
        post_migration_records=c_post.evidence,
        baseline_scan_ids=req.baseline_scan_ids,
        post_migration_scan_ids=req.post_migration_scan_ids,
        target_weakness_filter=req.target_weaknesses
    )
    return report.model_dump()


@router.get('/standards/mapping')
def standards_mapping():
    return get_all_standards()


def pcap_worker(payload):
    raw = base64.b64decode(payload['bytes'])
    res = PcapEngine.parse_pcap_bytes(raw)
    return res.model_dump()


class PcapRequest(BaseModel):
    raw_hex: Optional[str] = Field(default=None, max_length=MAX_BYTES * 2)
    with_pqc_hybrid: bool = True
    file_name: str = Field(default='capture.pcap', max_length=300)


@router.post('/scan/pcap', status_code=202)
def scan_pcap(req: PcapRequest, request: Request, project: str = Project):
    if req.raw_hex:
        try:
            raw = bytes.fromhex(req.raw_hex)
            if not raw or len(raw) > MAX_BYTES:
                raise ValueError()
        except ValueError:
            raise HTTPException(422, 'Supply valid hex representing a PCAP file up to 8 MiB')
    else:
        raw = PcapEngine.generate_synthetic_pcap(with_pqc_hybrid=req.with_pqc_hybrid)
    return enqueue(request, project, 'pcap', {'bytes': base64.b64encode(raw).decode(), 'file_name': req.file_name}, pcap_worker)


@router.post('/scan/pcap/synthetic', status_code=202)
def scan_pcap_synthetic(request: Request, project: str = Project, with_pqc_hybrid: bool = True):
    raw = PcapEngine.generate_synthetic_pcap(with_pqc_hybrid=with_pqc_hybrid)
    return enqueue(request, project, 'pcap', {'bytes': base64.b64encode(raw).decode(), 'file_name': 'synthetic_capture.pcap'}, pcap_worker)


@router.post('/scan/pcap/upload', status_code=202)
async def upload_pcap(request: Request, file: UploadFile = File(...), project: str = Project):
    raw = await file.read(MAX_BYTES + 1)
    await file.close()
    if not raw or len(raw) > MAX_BYTES:
        raise HTTPException(413, 'Upload must contain 1 byte to 8 MiB')
    return enqueue(request, project, 'pcap', {'bytes': base64.b64encode(raw).decode(), 'file_name': (file.filename or 'capture.pcap')[:300]}, pcap_worker)


class PcapAnalyzeRequest(BaseModel):
    raw_hex: Optional[str] = None
    with_pqc_hybrid: bool = True
    file_name: str = "capture.pcap"


@router.api_route('/experimental/pcap', methods=['GET', 'POST'])
def analyze_pcap_direct(req: Optional[PcapAnalyzeRequest] = None):
    if req and req.raw_hex:
        try:
            raw = bytes.fromhex(req.raw_hex)
        except ValueError:
            raise HTTPException(422, 'Invalid hex data for PCAP')
    else:
        with_pqc = req.with_pqc_hybrid if req else True
        raw = PcapEngine.generate_synthetic_pcap(with_pqc_hybrid=with_pqc)
    return PcapEngine.parse_pcap_bytes(raw).model_dump()



class RuntimeTraceRequest(BaseModel):
    target_command: list[str] | None = None
    target_code: str | None = None


@router.post('/experimental/runtime-trace')
def run_runtime_trace(req: RuntimeTraceRequest):
    if req.target_code:
        with tempfile.NamedTemporaryFile(suffix='.py', delete=False, mode='w') as tf:
            tf.write(req.target_code)
            tmp_path = tf.name
        try:
            return RuntimeTracer.execute_instrumented_run([sys.executable, tmp_path]).model_dump()
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
    cmd = req.target_command or [sys.executable, '-c', 'import hashlib; hashlib.sha256(b"ECDAT_RUNTIME_PROBE").hexdigest()']
    return RuntimeTracer.execute_instrumented_run(cmd).model_dump()


@router.get('/experimental/ebpf-capabilities')
def ebpf_capabilities():
    return EbpfTracer.inspect_capabilities().model_dump()


class EbpfTraceRequest(BaseModel):
    target_pid: int | None = None
    library_path: str = '/lib/x86_64-linux-gnu/libcrypto.so.3'
    duration_seconds: float = Field(default=2.0, ge=0.5, le=30.0)


@router.post('/experimental/ebpf-trace')
def run_ebpf_trace(req: EbpfTraceRequest):
    return EbpfTracer.trace_process(req.target_pid, req.library_path, req.duration_seconds).model_dump()


class CustomCryptoRequest(BaseModel):
    code: str = Field(min_length=1, max_length=500_000)
    file_path: str = Field(default='custom_crypto.py', max_length=300)


@router.post('/experimental/custom-crypto')
def detect_custom_crypto(req: CustomCryptoRequest):
    return CustomCryptoDetector.analyze_snippet(req.code, req.file_path).model_dump()


@router.get('/experimental/custom-crypto/benchmark')
def custom_crypto_benchmark():
    return CustomCryptoDetector.run_benchmark().model_dump()


class AutoPatchRequest(BaseModel):
    source_code: str = Field(min_length=1, max_length=500_000)
    file_path: str = Field(default='app.py', max_length=300)
    language: str = 'python'
    run_tests: bool = True


@router.post('/experimental/autopatch')
def generate_autopatch(req: AutoPatchRequest):
    patch = AutoPatchEngine.create_patch(req.source_code, req.file_path, req.language)
    if not patch:
        raise HTTPException(404, 'No applicable safe migration template matched the code.')
    if req.run_tests:
        patch = AutoPatchEngine.run_regression_test(patch)
    return patch.model_dump()


class QuantumEstimationRequest(BaseModel):
    target_algorithm: str = Field(default='RSA-2048', max_length=50)
    physical_error_rate: float = Field(default=1e-3, gt=0, le=0.01)
    cycle_time_us: float = Field(default=1.0, gt=0, le=1000.0)


@router.post('/risk/quantum-estimation')
def estimate_quantum_resources(req: QuantumEstimationRequest):
    return QuantumResourceEstimator.estimate_resources(
        req.target_algorithm, req.physical_error_rate, req.cycle_time_us
    ).model_dump()


@router.get('/risk/quantum-estimation/targets')
def list_quantum_estimation_targets():
    return QuantumResourceEstimator.list_supported_targets()


class BinaryMLRequest(BaseModel):
    raw_hex: str = Field(min_length=2, max_length=MAX_BYTES * 2)
    file_name: str = Field(default='binary.bin', max_length=300)


@router.post('/experimental/binary-ml')
def classify_binary_ml(req: BinaryMLRequest):
    try:
        raw = bytes.fromhex(req.raw_hex)
    except ValueError:
        raise HTTPException(422, 'Invalid hex data')
    return BinaryMLClassifier.classify_binary(raw, req.file_name).model_dump()


@router.api_route('/demo/sih-flow', methods=['GET', 'POST'])
def run_sih_demo():
    try:
        return SihDemoRunner.run_full_flow().model_dump()
    except Exception as exc:
        raise HTTPException(500, detail=f"SIH demo execution failed: {str(exc)}")



app.include_router(router, prefix='/api')

app.include_router(router)
app.add_api_route('/', health)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '8000')))
