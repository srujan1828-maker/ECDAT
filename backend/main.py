from contextlib import asynccontextmanager
from datetime import date
from fastapi.encoders import jsonable_encoder
import base64
import io
import json
import os
import re
import secrets
import sys
import tarfile
import tempfile
import zipfile
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

from fastapi import FastAPI, APIRouter, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator
from engine.scan_store import ScanStore
from engine.source_scan import scan_sources, LANGUAGES, LANGUAGE_ALIASES, is_manifest_file, normalize_language
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
from engine.github_engine import GitHubEngine
from engine.rag_engine import rag_engine
from engine.llm_engine import DeepSeekR1Engine


@asynccontextmanager
async def lifespan(app):
    app.state.store = ScanStore()
    app.state.latest_custom_loop = None
    app.state.uploads = {}
    yield
    app.state.store.close()


app = FastAPI(title='ECDAT API', version='3.0.0', lifespan=lifespan)
origins = [x.strip() for x in os.getenv('CORS_ORIGINS', 'http://localhost:3000').split(',') if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=False,
                   allow_methods=['GET', 'POST'], allow_headers=['Content-Type', 'Authorization'])


MAX_REQUEST_BYTES = 520 * 1024 * 1024  # 520 MiB request limit for large uploads
MAX_SOURCE_BYTES = 500 * 1024 * 1024   # 500 MiB source file bundle limit
MAX_SOURCE_FILES = 10000

SOURCE_CODE_EXTENSIONS = {
    '.py', '.c', '.cpp', '.h', '.hpp', '.cc', '.cxx', '.java', '.go',
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.rs', '.rb', '.php',
    '.cs', '.swift', '.kt', '.kts', '.scala', '.m', '.mm',
    '.json', '.yaml', '.yml', '.toml', '.xml', '.sql', '.sh', '.bash',
    '.txt', '.md', '.properties', '.env', '.ini', '.cfg', '.conf'
}

IGNORE_ARCHIVE_DIRS = {
    'node_modules', '.git', '.svn', '.hg', '__pycache__', '.venv', 'venv',
    '.idea', '.vscode', 'build', 'dist', 'target', '.next', '.cache'
}


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
            if len(body) > MAX_REQUEST_BYTES:
                return JSONResponse({'detail': 'Request exceeds 500 MiB'}, status_code=413)
        request._body = bytes(body)
    return await call_next(request)


router = APIRouter()
Project = Query(default='default', min_length=1, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')


class NetworkRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    port: int = Field(default=443, ge=1, le=65535)


class SourceFile(BaseModel):
    path: str = Field(min_length=1, max_length=500)
    content: str = Field(default='', max_length=MAX_SOURCE_BYTES)
    content_b64: Optional[str] = Field(default=None, max_length=MAX_SOURCE_BYTES * 2)
    language: str | None = None

    @model_validator(mode='after')
    def valid_file(self):
        if self.content_b64 and not self.content:
            try:
                decoded = base64.b64decode(self.content_b64.encode('ascii'))
                self.content = decoded.decode('utf-8', errors='replace')
            except Exception as e:
                raise ValueError(f'Invalid base64 encoding in content_b64: {e}')
        clean_path = self.path.replace('\\', '/')
        if clean_path.startswith('/') or '..' in clean_path.split('/'):
            raise ValueError('Use a relative file path without parent traversal')
        # Clients may send generic/unknown for README, configuration, and manifest files.
        # Resolve aliases here so these metadata files remain scannable instead of failing
        # validation before the source scanner can apply its generic pattern analysis.
        if self.language is not None:
            requested_language = str(self.language).strip().lower()
            if requested_language not in LANGUAGE_ALIASES:
                raise ValueError('Unsupported language')
            self.language = normalize_language(requested_language, clean_path)
        return self


class CodeRequest(BaseModel):
    source_code: str = Field(default='', max_length=50_000_000)
    source_code_b64: Optional[str] = Field(default=None, max_length=100_000_000)
    language: Literal['python', 'java', 'c_cpp', 'golang', 'javascript'] = 'python'

    @model_validator(mode='after')
    def valid_code(self):
        if self.source_code_b64 and not self.source_code:
            try:
                decoded = base64.b64decode(self.source_code_b64.encode('ascii'))
                self.source_code = decoded.decode('utf-8', errors='replace')
            except Exception as e:
                raise ValueError(f'Invalid base64 in source_code_b64: {e}')
        if not self.source_code:
            raise ValueError('source_code or source_code_b64 is required')
        return self


class SourcesRequest(BaseModel):
    files: list[SourceFile] = Field(min_length=1, max_length=MAX_SOURCE_FILES)

    @model_validator(mode='after')
    def valid_total(self):
        total = 0
        for f in self.files:
            if f.content:
                total += len(f.content.encode('utf-8', errors='replace'))
            elif f.content_b64:
                total += (len(f.content_b64) * 3) // 4
        if total > MAX_SOURCE_BYTES:
            raise ValueError('Source bundle exceeds 500 MiB')
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


def extract_source_files_from_archive(raw: bytes, filename: str) -> list[dict]:
    files = []
    total_bytes = 0
    fname = (filename or '').lower()
    if fname.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            for entry in z.infolist():
                if entry.is_dir():
                    continue
                clean_path = entry.filename.replace('\\', '/').lstrip('/')
                parts = clean_path.split('/')
                if any(p in ('..', '.') for p in parts) or any(p in IGNORE_ARCHIVE_DIRS or p.startswith('__MACOSX') for p in parts):
                    continue
                ext = Path(clean_path).suffix.lower()
                if ext not in SOURCE_CODE_EXTENSIONS and not is_manifest_file(clean_path):
                    continue
                if entry.file_size > MAX_SOURCE_BYTES or (total_bytes + entry.file_size) > MAX_SOURCE_BYTES:
                    raise ValueError('Unpacked source files exceed 500 MiB limit')
                if len(files) >= MAX_SOURCE_FILES:
                    break
                with z.open(entry) as stream:
                    content_bytes = stream.read(entry.file_size)
                try:
                    content_str = content_bytes.decode('utf-8-sig')
                except UnicodeDecodeError:
                    content_str = content_bytes.decode('latin-1', errors='replace')
                total_bytes += len(content_bytes)
                files.append({'path': clean_path, 'content': content_str})
    elif any(fname.endswith(ext) for ext in ('.tar.gz', '.tgz', '.tar')):
        mode = 'r:gz' if fname.endswith(('.tar.gz', '.tgz')) else 'r:'
        with tarfile.open(fileobj=io.BytesIO(raw), mode=mode) as tar:
            for member in tar.getmembers():
                if not member.isfile():
                    continue
                clean_path = member.name.replace('\\', '/').lstrip('/')
                parts = clean_path.split('/')
                if any(p in ('..', '.') for p in parts) or any(p in IGNORE_ARCHIVE_DIRS or p.startswith('__MACOSX') for p in parts):
                    continue
                ext = Path(clean_path).suffix.lower()
                if ext not in SOURCE_CODE_EXTENSIONS and not is_manifest_file(clean_path):
                    continue
                if member.size > MAX_SOURCE_BYTES or (total_bytes + member.size) > MAX_SOURCE_BYTES:
                    raise ValueError('Unpacked source files exceed 500 MiB limit')
                if len(files) >= MAX_SOURCE_FILES:
                    break
                f = tar.extractfile(member)
                if f:
                    content_bytes = f.read()
                    try:
                        content_str = content_bytes.decode('utf-8-sig')
                    except UnicodeDecodeError:
                        content_str = content_bytes.decode('latin-1', errors='replace')
                    total_bytes += len(content_bytes)
                    files.append({'path': clean_path, 'content': content_str})
    else:
        try:
            content_str = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            content_str = raw.decode('latin-1', errors='replace')
        files.append({'path': Path(filename).name or 'source_file.txt', 'content': content_str})

    if not files:
        raise ValueError('No valid source code or manifest files found in upload')
    return files


@router.post('/scan/sources/upload', status_code=202)
async def sources_upload(
    request: Request,
    file: Optional[UploadFile] = File(None),
    files: Optional[list[UploadFile]] = File(None),
    project: str = Project
):
    upload_list = []
    if files:
        upload_list.extend(files)
    if file:
        upload_list.append(file)
    if not upload_list:
        raise HTTPException(422, 'Provide a source file, ZIP archive, or list of source files')

    # If single archive (ZIP / TAR)
    if len(upload_list) == 1 and any((upload_list[0].filename or '').lower().endswith(ext) for ext in ('.zip', '.tar.gz', '.tgz', '.tar')):
        raw = await upload_list[0].read(MAX_SOURCE_BYTES + 1)
        await upload_list[0].close()
        if len(raw) > MAX_SOURCE_BYTES:
            raise HTTPException(413, 'Upload exceeds 500 MiB')
        try:
            parsed_files = extract_source_files_from_archive(raw, upload_list[0].filename or 'archive.zip')
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return enqueue(request, project, 'code', {'files': parsed_files}, lambda p: scan_sources(p['files']))

    # Multiple or single uncompressed source files via multipart
    total_size = 0
    parsed_files = []
    for f in upload_list:
        if len(parsed_files) >= MAX_SOURCE_FILES:
            break
        raw = await f.read(MAX_SOURCE_BYTES + 1 - total_size)
        await f.close()
        total_size += len(raw)
        if total_size > MAX_SOURCE_BYTES:
            raise HTTPException(413, 'Total source files exceed 500 MiB')
        clean_path = (f.filename or 'source.txt').replace('\\', '/').lstrip('/')
        parts = clean_path.split('/')
        if any(p in ('..', '.') for p in parts):
            continue
        try:
            content_str = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            content_str = raw.decode('latin-1', errors='replace')
        parsed_files.append({'path': clean_path, 'content': content_str})

    if not parsed_files:
        raise HTTPException(422, 'No valid source files uploaded')
    return enqueue(request, project, 'code', {'files': parsed_files}, lambda p: scan_sources(p['files']))


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
def scans(request: Request, project: str = Project, status: Optional[str] = None):
    if status and status not in {'queued', 'running', 'completed', 'failed', 'cancelled'}:
        raise HTTPException(422, 'Invalid scan status')
    return request.app.state.store.list(project, status)


@router.get('/scans/{scan_id}')
def scan(scan_id: str, request: Request, project: str = Project):
    result = request.app.state.store.get(scan_id, project)
    if result is None:
        raise HTTPException(404, 'Scan not found')
    return result


@router.get('/scans/{scan_id}/result')
def scan_result(scan_id: str, request: Request, project: str = Project):
    record = request.app.state.store.get(scan_id, project)
    if record is None:
        raise HTTPException(404, 'Scan not found')
    if record['status'] == 'failed':
        raise HTTPException(409, record.get('error') or 'Scan failed')
    if record['status'] != 'completed':
        raise HTTPException(409, f"Scan is {record['status']}")
    result = dict(record.get('result') or {})
    payload = request.app.state.store.get_payload(scan_id, project) or {}
    files = payload.get('files') or []
    if files:
        result.setdefault('source_files', [
            {'path': item.get('path', 'source.txt'), 'language': item.get('language')}
            for item in files
        ])
        result.setdefault('source_file_count', len(files))
    if files and len(files) == 1:
        result.setdefault('source_code', files[0].get('content', ''))
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


class ApplyPatchRequest(BaseModel):
    file_path: str = Field(min_length=1, max_length=500)
    patched_code: str = Field(min_length=1, max_length=10_000_000)
    backup: bool = True
    workspace_root: Optional[str] = None


@router.post('/experimental/autopatch/apply')
def apply_autopatch(req: ApplyPatchRequest):
    try:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        root = req.workspace_root or base_dir
        res = AutoPatchEngine.apply_patch(
            file_path=req.file_path,
            patched_code=req.patched_code,
            backup=req.backup,
            workspace_root=root,
        )
        return res
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        raise HTTPException(500, f"Failed to apply patch: {e}")


class CodebasePatchRequest(BaseModel):
    files: list[SourceFile] = Field(min_length=1, max_length=MAX_SOURCE_FILES)


@router.post('/migration/patch-codebase')
def patch_codebase_json(req: CodebasePatchRequest):
    files_payload = []
    for f in req.files:
        files_payload.append({
            "path": f.path,
            "content": f.content,
            "language": f.language
        })
    return AutoPatchEngine.patch_entire_codebase(files_payload)


@router.post('/migration/patch-codebase/upload')
async def patch_codebase_upload(
    file: Optional[UploadFile] = File(None),
    files: Optional[list[UploadFile]] = File(None),
):
    upload_list = []
    if files:
        upload_list.extend(files)
    if file:
        upload_list.append(file)
    if not upload_list:
        raise HTTPException(422, 'Provide a source file, ZIP archive, or list of source files')

    if len(upload_list) == 1 and any((upload_list[0].filename or '').lower().endswith(ext) for ext in ('.zip', '.tar.gz', '.tgz', '.tar')):
        raw = await upload_list[0].read(MAX_SOURCE_BYTES + 1)
        await upload_list[0].close()
        if len(raw) > MAX_SOURCE_BYTES:
            raise HTTPException(413, 'Upload exceeds 500 MiB')
        try:
            parsed_files = extract_source_files_from_archive(raw, upload_list[0].filename or 'archive.zip')
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        return AutoPatchEngine.patch_entire_codebase(parsed_files)

    parsed_files = []
    total_size = 0
    for f in upload_list:
        raw = await f.read(MAX_SOURCE_BYTES + 1 - total_size)
        await f.close()
        total_size += len(raw)
        try:
            content_str = raw.decode('utf-8-sig')
        except UnicodeDecodeError:
            content_str = raw.decode('latin-1', errors='replace')
        clean_path = (f.filename or 'source.txt').replace('\\', '/').lstrip('/')
        parsed_files.append({'path': clean_path, 'content': content_str})

    return AutoPatchEngine.patch_entire_codebase(parsed_files)


@router.post('/migration/download-patched-zip')
def download_patched_zip_endpoint(req: CodebasePatchRequest):
    files_payload = []
    for f in req.files:
        files_payload.append({
            "path": f.path,
            "content": f.content,
            "language": f.language
        })
    patch_res = AutoPatchEngine.patch_entire_codebase(files_payload)
    zip_bytes = AutoPatchEngine.create_patched_zip(files_payload, patch_res)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="ecdat_patched_codebase.zip"',
            "Content-Length": str(len(zip_bytes)),
        }
    )


@router.post('/migration/download-patched-zip/upload')
async def download_patched_zip_upload(
    file: Optional[UploadFile] = File(None),
    files: Optional[list[UploadFile]] = File(None),
):
    upload_list = []
    if files:
        upload_list.extend(files)
    if file:
        upload_list.append(file)
    if not upload_list:
        raise HTTPException(422, 'Provide a source file, ZIP archive, or list of source files')

    if len(upload_list) == 1 and any((upload_list[0].filename or '').lower().endswith(ext) for ext in ('.zip', '.tar.gz', '.tgz', '.tar')):
        raw = await upload_list[0].read(MAX_SOURCE_BYTES + 1)
        await upload_list[0].close()
        parsed_files = extract_source_files_from_archive(raw, upload_list[0].filename or 'archive.zip')
    else:
        parsed_files = []
        for f in upload_list:
            raw = await f.read()
            await f.close()
            try:
                content_str = raw.decode('utf-8-sig')
            except UnicodeDecodeError:
                content_str = raw.decode('latin-1', errors='replace')
            clean_path = (f.filename or 'source.txt').replace('\\', '/').lstrip('/')
            parsed_files.append({'path': clean_path, 'content': content_str})

    patch_res = AutoPatchEngine.patch_entire_codebase(parsed_files)
    zip_bytes = AutoPatchEngine.create_patched_zip(parsed_files, patch_res)
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="ecdat_patched_codebase.zip"',
            "Content-Length": str(len(zip_bytes)),
        }
    )


class GitHubPullRequest(BaseModel):
    url: str = Field(min_length=3, max_length=500)
    ref: Optional[str] = Field(default=None, max_length=100)
    subpath: Optional[str] = Field(default=None, max_length=300)
    token: Optional[str] = Field(default=None, max_length=200)


@router.post('/github/pull')
def github_pull(req: GitHubPullRequest):
    try:
        data = GitHubEngine.fetch_repository_files(
            url=req.url,
            ref=req.ref,
            subpath=req.subpath,
            token=req.token,
        )
        return data
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"GitHub pull failed: {exc}")


@router.post('/scan/github', status_code=202)
@router.post('/github/scan', status_code=202)
def github_scan(req: GitHubPullRequest, request: Request, project: str = Project):
    try:
        repo_data = GitHubEngine.fetch_repository_files(
            url=req.url,
            ref=req.ref,
            subpath=req.subpath,
            token=req.token,
        )
        files = repo_data.get("files", [])
        return enqueue(request, project, 'code', {'files': files}, lambda p: scan_sources(p['files']))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, f"GitHub scan failed: {exc}")


class RAGQueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=500)
    language: Optional[str] = None
    category: Optional[str] = None
    top_k: int = Field(default=3, ge=1, le=10)


@router.post('/ai/rag/query')
def query_rag_standards(req: RAGQueryRequest):
    results = rag_engine.retrieve(
        query=req.query,
        language=req.language,
        category=req.category,
        top_k=req.top_k,
    )
    return {
        "query": req.query,
        "language": req.language,
        "total_results": len(results),
        "results": results,
    }


class AIRefactorRequest(BaseModel):
    file_path: str = Field(default="snippet.py", max_length=500)
    source_code: str = Field(min_length=1, max_length=10_000_000)
    language: str = "python"
    findings: Optional[list[dict]] = None
    model: Optional[str] = None


@router.post('/ai/refactor')
def ai_refactor_endpoint(req: AIRefactorRequest):
    return DeepSeekR1Engine.refactor_code(
        file_path=req.file_path,
        source_code=req.source_code,
        language=req.language,
        findings=req.findings,
        model=req.model or "deepseek-ai/deepseek-r1",
    )


class AIExplainRequest(BaseModel):
    primitive: str = Field(min_length=1, max_length=100)
    issue: str = Field(default="", max_length=200)
    code_context: Optional[str] = None


@router.post('/ai/explain')
def ai_explain_endpoint(req: AIExplainRequest):
    return DeepSeekR1Engine.explain_finding(
        primitive=req.primitive,
        issue=req.issue,
        code_context=req.code_context,
    )


class AITriageRequest(BaseModel):
    code_snippet: str = Field(min_length=1, max_length=500_000)
    file_path: str = Field(default='snippet.py', max_length=500)
    api_key: Optional[str] = None


@router.post('/ai/triage')
def ai_triage(req: AITriageRequest):
    language = normalize_language(Path(req.file_path).suffix.lstrip('.') or 'python', req.file_path)
    result = scan_sources([{'path': req.file_path, 'content': req.code_snippet, 'language': language}])
    return {
        'mode': 'deterministic_triage', 'status': result.get('status', 'success'),
        'summary': f"Identified {len(result.get('findings', []))} cryptographic finding(s).",
        'findings': result.get('findings', []), 'coverage': result.get('coverage', []),
        'limitations': result.get('limitations', []),
    }


class MigrationAdvisoryRequest(BaseModel):
    current_algorithm: str = Field(min_length=1, max_length=100)
    cryptographic_role: str = Field(default='KEY_EXCHANGE', max_length=100)
    data_lifetime_years: int = Field(default=15, ge=0, le=200)
    environment: str = Field(default='Production', max_length=100)
    api_key: Optional[str] = None


@router.post('/ai/migration-advisory')
def ai_migration_advisory(req: MigrationAdvisoryRequest):
    algorithm = req.current_algorithm.upper()
    if any(name in algorithm for name in ('RSA', 'DH', 'ECDH')):
        target = 'ML-KEM-768 (FIPS 203)'
    elif any(name in algorithm for name in ('ECDSA', 'DSA', 'ED25519')):
        target = 'ML-DSA-65 (FIPS 204)'
    else:
        target = 'AES-256 and SHA-384, subject to protocol-specific review'
    return {
        'current_algorithm': req.current_algorithm, 'recommended_target': target,
        'priority': 'CRITICAL' if req.data_lifetime_years >= 10 else 'HIGH',
        'recommendation': f'Migrate {req.cryptographic_role} usage in {req.environment} to {target} using a hybrid transition and closed-loop verification.',
        'migration_steps': ['Inventory dependent assets', 'Introduce algorithm abstraction', 'Deploy a hybrid transition', 'Re-scan and verify retired weaknesses'],
        'evidence_basis': "Mosca's theorem and the NIST post-quantum standards mapping.",
    }


@router.post('/projects/{project_id}/ai/summary')
def project_ai_summary(project_id: str, request: Request):
    project = request.app.state.store.get_project(project_id)
    if project is None:
        raise HTTPException(404, 'Project not found')
    data = overview(request, project_id)
    return {
        'mode': 'evidence_based_summary', 'project': project['name'],
        'summary': f"{data['scan_count']} completed scans produced {data['kpis']['total_findings']} findings for {project['name']}.",
        'kpis': data['kpis'], 'recommended_action': 'Prioritize critical findings, plan deterministic migrations, and verify changes with a post-migration scan.',
        'limitations': data.get('limitations', []),
    }


DEMO_TARGETS = {
    "apex_pay": {
        "id": "apex_pay",
        "name": "ApexPay FinTech Banking Portal (Node.js)",
        "url": "http://localhost:8081",
        "relative_path": "demo_servers/website1_apex_pay/server.js",
        "description": "Enterprise Node.js payment gateway with MD5 password hashing and 56-bit DES card token encryption.",
    },
    "med_vault": {
        "id": "med_vault",
        "name": "MedVault Healthcare EHR Portal (Node.js)",
        "url": "http://localhost:8082",
        "relative_path": "demo_servers/website2_med_vault/server.js",
        "description": "Electronic health record portal with quantum-vulnerable 1024-bit RSA doctor digital prescription keys.",
    },
    "cipher_cloud": {
        "id": "cipher_cloud",
        "name": "CipherCloud Enterprise Storage (Node.js)",
        "url": "http://localhost:8083",
        "relative_path": "demo_servers/website3_cipher_cloud/server.js",
        "description": "Cloud document locker with obsolete 56-bit DES symmetric encryption and MD5 integrity verification.",
    },
}


def _get_target_abs_path(target_id: str) -> tuple[dict, str, str]:
    target = DEMO_TARGETS.get(target_id)
    if not target:
        raise HTTPException(404, f"Target '{target_id}' not found.")
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    abs_path = os.path.abspath(os.path.join(base_dir, target["relative_path"]))
    if not os.path.exists(abs_path):
        py_fallback = abs_path.replace("server.js", "app.py")
        if os.path.exists(py_fallback):
            abs_path = py_fallback
    ext = os.path.splitext(abs_path)[1].lower()
    lang = "javascript" if ext in (".js", ".mjs", ".cjs", ".ts") else "python"
    return target, abs_path, lang


@router.get('/demo/target/status')
def get_demo_target_status(target: str = "apex_pay"):
    info, abs_path, lang = _get_target_abs_path(target)
    exists = os.path.exists(abs_path)
    is_patched = False
    findings_count = 0
    if exists:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        if target in ("apex_pay", "cipher_cloud"):
            is_patched = (
                "createHash('sha256')" in content
                or 'createHash("sha256")' in content
                or "hashlib.sha256(" in content
            )
        elif target == "med_vault":
            is_patched = (
                "modulusLength: 3072" in content
                or "modulusLength:3072" in content
                or "key_size=3072" in content
            )
        scan_res = scan_sources([{"path": os.path.basename(abs_path), "content": content, "language": lang}])
        findings_count = len(scan_res.get("findings", []))

    backup_exists = os.path.exists(f"{abs_path}.bak")
    return {
        "target": info,
        "file_exists": exists,
        "is_patched": is_patched,
        "findings_count": findings_count,
        "backup_exists": backup_exists,
        "language": lang,
    }


@router.get('/demo/target/source')
def get_demo_target_source(target: str = "apex_pay"):
    info, abs_path, lang = _get_target_abs_path(target)
    if not os.path.exists(abs_path):
        raise HTTPException(404, f"Target file '{abs_path}' does not exist.")
    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    return {
        "target": info,
        "content": content,
        "language": lang,
        "filename": os.path.basename(abs_path),
    }


@router.post('/demo/target/scan')
def scan_demo_target(target: str = "apex_pay"):
    info, abs_path, lang = _get_target_abs_path(target)
    if not os.path.exists(abs_path):
        raise HTTPException(404, f"Target file '{abs_path}' does not exist.")
    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    res = scan_sources([{"path": info["relative_path"], "content": content, "language": lang}])
    return {
        "target": info,
        "findings": res.get("findings", []),
        "scan_summary": res.get("summary", {}),
        "language": lang,
    }


@router.post('/demo/target/patch')
def patch_demo_target(target: str = "apex_pay"):
    info, abs_path, lang = _get_target_abs_path(target)
    if not os.path.exists(abs_path):
        raise HTTPException(404, f"Target file '{abs_path}' does not exist.")
    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
        original = f.read()
    patch = AutoPatchEngine.create_patch(original, info["relative_path"], lang)
    if not patch:
        return {"status": "unaltered", "message": "No active weak patterns found or already patched.", "target": info}
    tested_patch = AutoPatchEngine.run_regression_test(patch)
    apply_res = AutoPatchEngine.apply_patch(abs_path, tested_patch.patched_code, backup=True)
    return {
        "status": "patched",
        "target": info,
        "pattern_id": tested_patch.pattern_id,
        "transformation": tested_patch.transformation_description,
        "unified_diff": tested_patch.unified_diff,
        "test_status": tested_patch.verification_status,
        "test_output": tested_patch.test_output,
        "backup_created": apply_res["backup_created"],
        "backup_path": apply_res["backup_path"],
        "weakness_eliminated": apply_res["weakness_eliminated"],
    }


@router.post('/demo/target/reset')
def reset_demo_target(target: str = "apex_pay"):
    info, abs_path, lang = _get_target_abs_path(target)
    backup_path = f"{abs_path}.bak"
    if os.path.exists(backup_path):
        import shutil
        shutil.copy2(backup_path, abs_path)
        return {"status": "reset", "message": f"Restored from backup {backup_path}", "target": info}
    with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()
    reverted = content
    if target in ("apex_pay", "cipher_cloud"):
        reverted = reverted.replace("createHash('sha256')", "createHash('md5')")
        reverted = reverted.replace('createHash("sha256")', 'createHash("md5")')
        reverted = reverted.replace("hashlib.sha256(", "hashlib.md5(")
    elif target == "med_vault":
        reverted = reverted.replace("modulusLength: 3072", "modulusLength: 1024")
        reverted = reverted.replace("modulusLength:3072", "modulusLength:1024")
        reverted = reverted.replace("key_size=3072", "key_size=1024")
    with open(abs_path, "w", encoding="utf-8") as f:
        f.write(reverted)
    return {"status": "reset", "message": "Reset to original vulnerable cryptographic state.", "target": info}


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


# -------------------------------------------------------------------------
# Frontend compatibility API
# These routes expose the persistent V4 store through the resource names used
# by the Next.js console. Keeping them here makes the browser and CLI APIs use
# the same source of truth instead of separate mock data.
# -------------------------------------------------------------------------

class ProjectRequest(BaseModel):
    id: str = Field(min_length=1, max_length=64, pattern=r'^[A-Za-z0-9_-]+$')
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default='', max_length=2000)
    organization: str = Field(default='', max_length=200)
    environment: Literal['Production', 'Staging', 'Development', 'Research', 'Other'] = 'Production'
    business_criticality: Literal['Critical', 'High', 'Medium', 'Low', 'Unknown'] = 'Unknown'
    data_sensitivity: Literal['Public', 'Internal', 'Confidential', 'Sensitive', 'Classified', 'Unknown'] = 'Unknown'
    data_lifetime_years: int = Field(default=10, ge=0, le=200)
    migration_target_date: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list, max_length=50)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=6, max_length=200)


class RegisterRequest(LoginRequest):
    name: str = Field(min_length=1, max_length=200)
    role: Literal['OWNER', 'ADMIN', 'SECURITY_ANALYST', 'VIEWER'] = 'SECURITY_ANALYST'


def _auth_response(user: dict) -> dict:
    return {
        'user_id': user['id'], 'email': user['email'], 'name': user['name'],
        'role': user['role'], 'token': secrets.token_urlsafe(32),
    }


@router.post('/auth/login')
def login(req: LoginRequest, request: Request):
    user = request.app.state.store.authenticate_user(req.email, req.password)
    if user is None:
        raise HTTPException(401, 'Invalid email or password')
    return _auth_response(user)


@router.post('/auth/register', status_code=201)
def register(req: RegisterRequest, request: Request):
    try:
        user = request.app.state.store.create_user(req.email, req.name, req.role, req.password)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return _auth_response(user)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=200)
    description: Optional[str] = Field(default=None, max_length=2000)
    organization: Optional[str] = Field(default=None, max_length=200)
    environment: Optional[Literal['Production', 'Staging', 'Development', 'Research', 'Other']] = None
    business_criticality: Optional[Literal['Critical', 'High', 'Medium', 'Low', 'Unknown']] = None
    data_sensitivity: Optional[Literal['Public', 'Internal', 'Confidential', 'Sensitive', 'Classified', 'Unknown']] = None
    data_lifetime_years: Optional[int] = Field(default=None, ge=0, le=200)
    migration_target_date: Optional[str] = None
    owner: Optional[str] = Field(default=None, max_length=200)
    tags: Optional[list[str]] = Field(default=None, max_length=50)


@router.get('/projects')
def list_projects(request: Request):
    return request.app.state.store.list_projects()


@router.post('/projects', status_code=201)
def create_project(req: ProjectRequest, request: Request):
    try:
        return request.app.state.store.save_project(req.model_dump(), create=True)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@router.get('/projects/{project_id}')
def get_project(project_id: str, request: Request):
    value = request.app.state.store.get_project(project_id)
    if value is None:
        raise HTTPException(404, 'Project not found')
    return value


@router.patch('/projects/{project_id}')
def update_project(project_id: str, req: ProjectUpdate, request: Request):
    if request.app.state.store.get_project(project_id) is None:
        raise HTTPException(404, 'Project not found')
    values = req.model_dump(exclude_unset=True)
    values['id'] = project_id
    return request.app.state.store.save_project(values)


@router.get('/projects/{project_id}/assets')
def project_assets(project_id: str, request: Request):
    return request.app.state.store.get_assets(project_id)


def _frontend_evidence(record: dict, asset_id: Optional[str] = None) -> dict:
    metadata = record.get('metadata') or {}
    provenance = record.get('provenance') or {}
    return {
        **record,
        'asset_id': asset_id or record.get('asset_id') or record.get('artifact_id'),
        'scan_id': provenance.get('scan_id', record.get('scan_id', '')),
        'project': record.get('project', ''),
        'evidence_type': record.get('observation_type', 'OBSERVATION'),
        'algorithm': metadata.get('algorithm') or record.get('symbol') or record.get('description', 'Unknown'),
        'location': record.get('location') or record.get('file_path') or provenance.get('location') or 'Unknown',
        'snippet': metadata.get('snippet') or record.get('raw_details', {}).get('snippet'),
        'rule_id': record.get('rule_id') or provenance.get('rule_id') or 'UNSPECIFIED',
    }


def _query_project_evidence(request: Request, project: str, level=None, asset_id=None, scan_id=None):
    query = 'SELECT asset_id, data FROM evidence WHERE project=?'
    params = [project]
    if level:
        query += ' AND level=?'
        params.append(level)
    if asset_id:
        query += ' AND asset_id=?'
        params.append(asset_id)
    if scan_id:
        query += ' AND scan_id=?'
        params.append(scan_id)
    query += ' ORDER BY created_at DESC'
    with request.app.state.store.connect() as db:
        rows = db.execute(query, params).fetchall()
    return [_frontend_evidence(json.loads(row['data']), row['asset_id']) for row in rows]


@router.get('/projects/{project_id}/evidence')
def project_evidence(project_id: str, request: Request):
    return _query_project_evidence(request, project_id)


@router.get('/evidence')
def evidence_alias(request: Request, project: str = Project, level: Optional[str] = None,
                   asset_id: Optional[str] = None, scan_id: Optional[str] = None):
    return _query_project_evidence(request, project, level, asset_id, scan_id)


@router.get('/agility/assessment')
def project_agility(request: Request, project: str = Project):
    assets = request.app.state.store.get_assets(project)
    scans = request.app.state.store.list(project, 'completed')
    hardcoded = sum(1 for asset in assets if 'source' in str(asset.get('artifact_id', '')).lower())
    assessment = calculate_crypto_agility(
        hardcoded_primitives_count=hardcoded,
        abstracted_primitives_count=max(0, len(assets) - hardcoded),
        has_provider_abstraction=False,
        has_pqc_hybrid_support=any('ml-' in str(a.get('algorithm', '')).lower() for a in assets),
        automated_cert_rotation=False,
        uses_config_driven_crypto=False,
    )
    score = round(float(assessment.get('cai_score', 0)) * 10, 1)
    state = 'OBSERVED' if assets else 'UNKNOWN'
    names = ['Algorithm Substitution', 'Protocol Negotiation', 'Configuration', 'Dependencies', 'Certificates', 'Deployment', 'Validation']
    return {
        'overall_score': score,
        'total_assets_evaluated': len(assets),
        'total_scans_evaluated': len(scans),
        'dimensions': [{'name': name, 'state': state, 'desc': f'{name} capability derived from collected project evidence.', 'evidence_basis': f'{len(assets)} assets across {len(scans)} completed scans.'} for name in names],
        'details': assessment,
    }


class MoscaProjectRequest(BaseModel):
    project_id: str = Field(min_length=1, max_length=64)
    data_sensitivity_years: int = Field(default=10, ge=0, le=200)
    migration_time_years: float = Field(default=3, ge=0, le=100)
    crqc_horizon_override: Optional[int] = Field(default=None, ge=1, le=200)


@router.post('/quantum/mosca-project-scan')
def project_mosca(req: MoscaProjectRequest, request: Request):
    assets = request.app.state.store.get_assets(req.project_id)
    grouped = {}
    for asset in assets:
        algorithm = asset.get('algorithm') or asset.get('name') or 'Unknown'
        grouped[algorithm] = grouped.get(algorithm, 0) + 1
    results = []
    for algorithm, count in grouped.items():
        quantum_vulnerable = any(x in algorithm.upper() for x in ('RSA', 'ECDSA', 'ECDH', 'DH'))
        z = req.crqc_horizon_override or 10
        deficit = req.data_sensitivity_years + req.migration_time_years - z
        exposed = quantum_vulnerable and deficit > 0
        results.append({
            'algorithm': algorithm, 'key_size': None,
            'x_sensitivity_years': req.data_sensitivity_years,
            'y_migration_years': req.migration_time_years,
            'z_threat_horizon_years': z,
            'quantum_deficit_years': max(0, deficit),
            'harvest_now_risk': exposed,
            'risk_level': 'CRITICAL' if exposed else ('LOW' if quantum_vulnerable else 'SAFE'),
            'risk_score': 100 if exposed else (25 if quantum_vulnerable else 0),
            'explanation': 'Mosca inequality X + Y > Z applies.' if exposed else 'No current Mosca deficit was identified.',
            'recommendation': 'Prioritize migration to an applicable NIST PQC standard.' if quantum_vulnerable else 'Maintain controls and continue monitoring.',
            'literature_reference': "Mosca's theorem (X + Y > Z)", 'asset_count': count,
        })
    return {'results': results, 'message': '' if results else 'Run a scan to calculate project-specific HNDL exposure.'}


class PatchFromScanRequest(BaseModel):
    scan_id: str = Field(min_length=1, max_length=100)
    project_id: str = Field(default='default', min_length=1, max_length=64)
    selected_patterns: list[str] = Field(default_factory=list, max_length=100)
    file_path: str = Field(default='app.py', max_length=500)
    override_code: Optional[str] = Field(default=None, max_length=500_000)


@router.post('/patch/from-scan')
def patch_from_scan(req: PatchFromScanRequest, request: Request):
    record = request.app.state.store.get(req.scan_id, req.project_id)
    if record is None or record['status'] != 'completed':
        raise HTTPException(404, 'Completed source scan not found')
    payload = request.app.state.store.get_payload(req.scan_id, req.project_id) or {}
    files = payload.get('files') or []
    if req.override_code is not None:
        files = [{'path': req.file_path, 'content': req.override_code, 'language': files[0].get('language', 'python') if files else 'python'}]
    if not files:
        raise HTTPException(422, 'The scan does not contain source code that can be patched')
    patch_result = AutoPatchEngine.patch_entire_codebase(
        files, selected_patterns=req.selected_patterns or None
    )
    patched_files = patch_result.get('patched_files', [])
    if not patched_files:
        raise HTTPException(404, 'No applicable safe migration template matched the scan')
    failed = [item for item in patched_files if item.get('verification_status') not in {'passed', 'static_verified'}]
    if failed:
        raise HTTPException(422, f"Patch verification failed for {failed[0]['path']}: {failed[0].get('test_output', '')}")
    patched_lookup = {item['path']: item['patched_code'] for item in patched_files}
    output_files = [
        {**item, 'content': patched_lookup.get(item['path'], item.get('content', ''))}
        for item in files
    ]
    post_scan = enqueue(
        request,
        req.project_id,
        'code',
        {'files': output_files},
        lambda payload: scan_sources(payload['files']),
    )
    first = patched_files[0]
    combined_diff = '\n'.join(item.get('unified_diff', '') for item in patched_files)
    patterns = [pattern for item in patched_files for pattern in item.get('pattern_id', '').split('+') if pattern]
    value = {
        'pattern_id': '+'.join(patterns),
        'target_language': first.get('language', 'multi'),
        'file_path': first['path'],
        'original_code': first['original_code'],
        'patched_code': first['patched_code'],
        'unified_diff': combined_diff,
        'transformation_description': ' | '.join(item.get('transformation', '') for item in patched_files),
        'verification_status': 'passed' if all(item.get('verification_status') == 'passed' for item in patched_files) else 'static_verified',
        'test_output': '\n'.join(f"{item['path']}: {item.get('test_output', '')}" for item in patched_files),
        're_scan_summary': patch_result['summary'],
        'patched_files': patched_files,
        'project_file_count': len(files),
        'project_archive_available': True,
    }
    value.update({
        'total_patched': patch_result['summary']['vulnerabilities_remediated'],
        'baseline_scan_id': req.scan_id,
        'post_migration_scan_id': post_scan['id'],
        'applied': True,
        'execution_logs': [
            f'[ SCAN ] Loaded completed scan {req.scan_id[:8]}',
            f"[ PATCH ] Patched {len(patched_files)} of {len(files)} project files",
            f"[ VERIFY ] Remediated {patch_result['summary']['vulnerabilities_remediated']} findings with real regression/static checks",
            f"[ RESCAN ] Queued post-migration scan {post_scan['id'][:8]}",
        ],
    })
    return value


@router.post('/patch/from-scan/download')
def download_patch_from_scan(req: PatchFromScanRequest, request: Request):
    record = request.app.state.store.get(req.scan_id, req.project_id)
    if record is None or record['status'] != 'completed':
        raise HTTPException(404, 'Completed source scan not found')
    payload = request.app.state.store.get_payload(req.scan_id, req.project_id) or {}
    files = payload.get('files') or []
    if not files:
        raise HTTPException(422, 'The scan does not contain a source project')
    patch_result = AutoPatchEngine.patch_entire_codebase(
        files, selected_patterns=req.selected_patterns or None
    )
    if not patch_result.get('patched_files'):
        raise HTTPException(404, 'No applicable safe migration template matched the scan')
    zip_bytes = AutoPatchEngine.create_patched_zip(files, patch_result)
    return Response(
        content=zip_bytes,
        media_type='application/zip',
        headers={
            'Content-Disposition': 'attachment; filename="ecdat_patched_project.zip"',
            'Content-Length': str(len(zip_bytes)),
        },
    )


class CustomLoopRequest(BaseModel):
    target_type: Literal['source', 'binary'] = 'source'
    file_name: str = Field(default='app.py', max_length=500)
    language: str = Field(default='python', max_length=50)
    preset_name: Optional[str] = Field(default=None, max_length=100)
    source_code: Optional[str] = Field(default=None, max_length=500_000)
    binary_hex: Optional[str] = Field(default=None, max_length=MAX_BYTES * 2)


@router.post('/custom-loop/run')
def run_custom_loop(req: CustomLoopRequest, request: Request):
    import time
    import uuid

    started = time.perf_counter()
    if req.target_type != 'source' or not req.source_code:
        raise HTTPException(422, 'Automated remediation currently requires a source-code target')
    before = scan_sources([{'path': req.file_name, 'content': req.source_code, 'language': req.language}])
    patch = AutoPatchEngine.create_patch(req.source_code, req.file_name, req.language)
    if patch is None:
        raise HTTPException(404, 'No deterministic remediation is available for this target')
    patch = AutoPatchEngine.run_regression_test(patch)
    after = scan_sources([{'path': req.file_name, 'content': patch.patched_code, 'language': req.language}])
    before_findings = before.get('findings', [])
    after_findings = after.get('findings', [])
    retired_names = sorted({f.get('primitive', 'Unknown') for f in before_findings} - {f.get('primitive', 'Unknown') for f in after_findings})
    introduced_names = sorted({f.get('primitive', 'Unknown') for f in after_findings} - {f.get('primitive', 'Unknown') for f in before_findings})
    retired = [{'primitive': name, 'category': 'retired weakness', 'surface': 'source', 'location': req.file_name, 'severity': 'HIGH', 'description': f'{name} was removed by the deterministic patch.'} for name in retired_names]
    introduced = [{'primitive': name, 'category': 'modern protection', 'surface': 'source', 'location': req.file_name, 'severity': 'LOW', 'description': f'{name} was introduced by the deterministic patch.'} for name in introduced_names]
    regressions = [{'primitive': f.get('primitive', 'Unknown'), 'category': 'regression', 'surface': 'source', 'location': req.file_name, 'severity': f.get('severity', 'HIGH'), 'description': f.get('issue', 'Finding remains after remediation.')} for f in after_findings]
    result = {
        'run_id': str(uuid.uuid4()), 'target_name': req.file_name,
        'verdict': 'VERIFIED' if not regressions and patch.verification_status in ('passed', 'static_verified') else 'NOT_VERIFIED',
        'total_duration_ms': round((time.perf_counter() - started) * 1000),
        'before_state': {'code': req.source_code, 'critical_vulnerabilities': len(before_findings), 'security_score': max(0, 100 - len(before_findings) * 20), 'quantum_deficit_years': 13 if before_findings else 0, 'crypto_agility_score': 2.5},
        'after_state': {'code': patch.patched_code, 'critical_vulnerabilities': len(after_findings), 'security_score': max(0, 100 - len(after_findings) * 20), 'quantum_deficit_years': 0 if not after_findings else 13, 'crypto_agility_score': 7.5},
        'transformation_description': patch.transformation_description,
        'unified_diff': patch.unified_diff,
        'regression_test': {'status': patch.verification_status, 'code': patch.generated_regression_test, 'output': patch.test_output or ''},
        'verification_report': {'retired_weaknesses': retired, 'introduced_protections': introduced, 'persisting_risks': regressions, 'regressions': regressions},
        'cbom_summary': {'components_count': len(after_findings)},
    }
    request.app.state.latest_custom_loop = result
    return result


@router.get('/custom-loop/latest')
def latest_custom_loop(request: Request):
    if request.app.state.latest_custom_loop is None:
        raise HTTPException(404, 'No custom remediation run has completed yet')
    return request.app.state.latest_custom_loop


@router.post('/upload/chunk')
async def upload_chunk(request: Request):
    upload_id = request.headers.get('x-upload-id', '')
    filename = request.headers.get('x-filename', 'upload.bin')[:300]
    surface = request.headers.get('x-surface', '')
    project = request.headers.get('x-project-id', 'default')
    try:
        index = int(request.headers.get('x-chunk-index', '-1'))
        total = int(request.headers.get('x-total-chunks', '0'))
    except ValueError as exc:
        raise HTTPException(422, 'Invalid chunk metadata') from exc
    if not re.fullmatch(r'[A-Za-z0-9-]{8,100}', upload_id) or surface not in {'code', 'binary'}:
        raise HTTPException(422, 'Invalid upload identifier or surface')
    if not (0 <= index < total <= 300):
        raise HTTPException(422, 'Invalid chunk index or count')
    chunk = await request.body()
    if not chunk or len(chunk) > 3 * 1024 * 1024:
        raise HTTPException(413, 'Each upload chunk must be between 1 byte and 3 MiB')
    state = request.app.state.uploads.setdefault(upload_id, {
        'filename': filename, 'surface': surface, 'project': project,
        'total': total, 'chunks': {}, 'status': 'uploading', 'scan_job_id': None,
    })
    if any((state['filename'] != filename, state['surface'] != surface,
            state['project'] != project, state['total'] != total)):
        raise HTTPException(409, 'Chunk metadata does not match the existing upload')
    state['chunks'][index] = bytes(chunk)
    size = sum(len(value) for value in state['chunks'].values())
    limit = MAX_SOURCE_BYTES if surface == 'code' else MAX_BYTES
    if size > limit:
        request.app.state.uploads.pop(upload_id, None)
        raise HTTPException(413, f'Assembled {surface} upload exceeds the supported size limit')
    if len(state['chunks']) == total:
        raw = b''.join(state['chunks'][i] for i in range(total))
        if surface == 'code':
            try:
                files = extract_source_files_from_archive(raw, filename)
            except (ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
                state['status'] = 'failed'
                state['error'] = str(exc)
                raise HTTPException(422, str(exc)) from exc
            job = enqueue(request, project, 'code', {'files': files}, lambda p: scan_sources(p['files']))
        else:
            payload = {'bytes': base64.b64encode(raw).decode(), 'file_name': filename}
            job = enqueue(request, project, 'binary', payload, binary_worker)
        state.update({'status': 'processing', 'scan_job_id': job['id'], 'chunks': {}})
    return {'upload_id': upload_id, 'status': state['status'], 'received_chunks': len(state['chunks']), 'total_chunks': total, 'scan_job_id': state['scan_job_id']}


@router.get('/upload/{upload_id}/status')
def upload_status(upload_id: str, request: Request):
    state = request.app.state.uploads.get(upload_id)
    if state is None:
        raise HTTPException(404, 'Upload not found')
    if state.get('scan_job_id'):
        scan = request.app.state.store.get(state['scan_job_id'], state['project'])
        if scan and scan['status'] in {'completed', 'failed', 'cancelled'}:
            state['status'] = scan['status']
            if scan.get('error'):
                state['error'] = scan['error']
    return {key: value for key, value in state.items() if key != 'chunks'}


class ShorDemoRequest(BaseModel):
    message: str = Field(default='ECDAT quantum demonstration', max_length=1000)
    key_size: int = Field(default=512, ge=8, le=4096)


@router.post('/quantum/shor-demo')
def shor_demo(req: ShorDemoRequest):
    estimate = QuantumResourceEstimator.estimate_resources(
        f'RSA-{req.key_size}' if req.key_size in (1024, 2048, 3072, 4096) else 'RSA-2048',
        1e-3, 1.0,
    ).model_dump()
    return {
        'status': 'theoretical_simulation', 'message': req.message,
        'input_key_size': req.key_size, 'estimate': estimate,
        'execution_steps': [
            f'[ INIT ] Loaded RSA-{req.key_size} demonstration parameters',
            '[ MODEL ] Constructed Shor order-finding resource model',
            f"[ QUBITS ] Estimated {estimate['physical_qubits_estimate']:,} physical qubits",
            '[ NOTICE ] No private key was factored; this is a resource simulation',
        ],
        'disclaimer': 'Resource-estimation demonstration only; no cryptographic key was attacked.',
    }


@router.get('/quantum/timeline-summary')
def quantum_timeline_summary(request: Request, project: str = Project):
    project_data = request.app.state.store.get_project(project)
    assets = request.app.state.store.get_assets(project)
    vulnerable = [a for a in assets if any(x in str(a.get('algorithm') or a.get('name', '')).upper() for x in ('RSA', 'ECDSA', 'ECDH', 'DH'))]
    lifetime = (project_data or {}).get('data_lifetime_years', 10)
    return {
        'project': project, 'data_lifetime_years': lifetime,
        'quantum_vulnerable_assets': len(vulnerable),
        'hndl_exposed_assets': len(vulnerable) if lifetime + 3 > 10 else 0,
        'migration_time_years': 3, 'crqc_horizon_years': 10,
        'status': 'AT_RISK' if vulnerable and lifetime + 3 > 10 else ('MONITOR' if vulnerable else 'NO_EVIDENCE'),
    }


class ReportRequest(BaseModel):
    report_type: str = Field(default='EXECUTIVE', max_length=100)


@router.post('/projects/{project_id}/reports/generate')
def generate_project_report(project_id: str, req: ReportRequest, request: Request):
    project = request.app.state.store.get_project(project_id)
    if project is None:
        raise HTTPException(404, 'Project not found')
    return {
        'schema_version': '1.0', 'report_type': req.report_type,
        'generated_at': date.today().isoformat(), 'project': project,
        'overview': overview(request, project_id),
        'assets': request.app.state.store.get_assets(project_id),
        'evidence': _query_project_evidence(request, project_id),
    }


@router.get('/reports/generate')
def generate_report_html(request: Request, project: str = Project, format: str = 'html'):
    project_data = request.app.state.store.get_project(project)
    if project_data is None:
        raise HTTPException(404, 'Project not found')
    report = {
        'project': project_data,
        'overview': overview(request, project),
        'assets': request.app.state.store.get_assets(project),
    }
    if format != 'html':
        return report
    import html
    content = html.escape(json.dumps(jsonable_encoder(report), indent=2))
    return Response(
        content=f'<!doctype html><html><head><meta charset="utf-8"><title>ECDAT Report</title></head><body><h1>ECDAT Project Report</h1><pre>{content}</pre></body></html>',
        media_type='text/html',
    )


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
