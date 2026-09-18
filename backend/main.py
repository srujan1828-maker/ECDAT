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
from typing import Literal

_backend_dir = str(Path(__file__).resolve().parent)
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

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


@router.get('/overview')
def overview(request: Request, project: str = Project):
    records = [r for r in request.app.state.store.list(project) if r['status'] == 'completed']
    nodes, links, findings = [], [], []
    for record in records:
        result = record['result']
        evidence = result.get('findings', result.get('detections', []))
        if record['kind'] == 'network':
            evidence = [{'primitive': result['cipher_name'], 'severity': 'LOW'}]
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


@router.get('/graph')
def get_crypto_graph(request: Request, project: str = Project):
    records = [r for r in request.app.state.store.list(project) if r['status'] == 'completed']
    if not records:
        return CryptoKnowledgeGraph().export_for_ui()
    kg = CryptoKnowledgeGraph.from_scans(records, app_name=project)
    return kg.export_for_ui()


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
    raw_hex: str = Field(min_length=48, max_length=MAX_BYTES * 2)
    file_name: str = Field(default='capture.pcap', max_length=300)


@router.post('/scan/pcap', status_code=202)
def scan_pcap(req: PcapRequest, request: Request, project: str = Project):
    try:
        raw = bytes.fromhex(req.raw_hex)
        if not raw or len(raw) > MAX_BYTES:
            raise ValueError()
    except ValueError:
        raise HTTPException(422, 'Supply valid hex representing a PCAP file up to 8 MiB')
    return enqueue(request, project, 'pcap', {'bytes': base64.b64encode(raw).decode(), 'file_name': req.file_name}, pcap_worker)


@router.post('/scan/pcap/upload', status_code=202)
async def upload_pcap(request: Request, file: UploadFile = File(...), project: str = Project):
    raw = await file.read(MAX_BYTES + 1)
    await file.close()
    if not raw or len(raw) > MAX_BYTES:
        raise HTTPException(413, 'Upload must contain 1 byte to 8 MiB')
    return enqueue(request, project, 'pcap', {'bytes': base64.b64encode(raw).decode(), 'file_name': (file.filename or 'capture.pcap')[:300]}, pcap_worker)


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


@router.post('/demo/sih-flow')
def run_sih_demo():
    return SihDemoRunner.run_full_flow().model_dump()


app.include_router(router, prefix='/api')
app.include_router(router)
app.add_api_route('/', health)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '8000')))
