from contextlib import asynccontextmanager
import base64
import os
import re
import secrets
from typing import Literal
from fastapi import FastAPI, APIRouter, File, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, model_validator
from engine.scan_store import ScanStore
from engine.source_scan import scan_sources, LANGUAGES
from engine.binary_deep import scan_upload, MAX_BYTES
from engine.network_prober import probe_tls_endpoint
from engine.cbom_generator import generate_cyclonedx_cbom
from engine.agility_engine import calculate_crypto_agility
from engine.migration_simulator import simulate_pqc_migration_roadmap
from engine.quantum_risk import calculate_mosca_risk


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
    return enqueue(request, project, 'network', req.model_dump(), lambda p: probe_tls_endpoint(p['target'], p['port']))


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


class MoscaRequest(BaseModel):
    x: int = Field(default=10, ge=0, le=100)
    y: int = Field(default=4, ge=0, le=100)
    z: int = Field(default=8, ge=0, le=100)


@router.post('/risk/mosca')
def mosca(req: MoscaRequest):
    return calculate_mosca_risk(req.x, req.y, req.z)


app.include_router(router, prefix='/api')
app.include_router(router)
app.add_api_route('/', health)

if __name__ == '__main__':
    import uvicorn
    uvicorn.run('main:app', host=os.getenv('HOST', '127.0.0.1'), port=int(os.getenv('PORT', '8000')))
