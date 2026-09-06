from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio

from engine.network_prober import probe_tls_endpoint
from engine.ast_scanner import scan_code, generate_remediation_snippet
from engine.polyglot_scanner import scan_polyglot_code, POLYGLOT_SAMPLES, POLYGLOT_REMEDIATIONS
from engine.binary_scanner import scan_binary_data, generate_sample_binary_blob
from engine.agility_engine import calculate_crypto_agility
from engine.migration_simulator import simulate_pqc_migration_roadmap
from engine.quantum_risk import calculate_mosca_risk
from engine.cbom_generator import generate_cyclonedx_cbom
from engine.demo_data import DEMO_NETWORK, DEMO_CODE
from engine.knowledge_graph import kg

app = FastAPI(
    title="ECDAT API",
    description="Enterprise Cryptographic Discovery & Analysis Tool — SIH26164 (NTRO)",
    version="2.0.0",
)

import os

cors_env = os.getenv("CORS_ORIGINS", "")
allowed_origins = [
    "http://localhost:3000", "http://127.0.0.1:3000",
    "http://localhost:3001", "http://127.0.0.1:3001",
]
if cors_env:
    extra_origins = [orig.strip() for orig in cors_env.split(",") if orig.strip()]
    if "*" in extra_origins:
        allowed_origins = ["*"]
    else:
        allowed_origins.extend(extra_origins)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True if "*" not in allowed_origins else False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request models ─────────────────────────────────────────────────────────────

class NetworkScanRequest(BaseModel):
    target: str
    port: int = 443

class CodeScanRequest(BaseModel):
    source_code: str
    language: str = "python"

class BinaryScanRequest(BaseModel):
    raw_hex: Optional[str] = None
    file_name: Optional[str] = "firmware_telemetry.bin"

class AgilityRequest(BaseModel):
    hardcoded_primitives_count: int = 3
    abstracted_primitives_count: int = 1
    has_provider_abstraction: bool = False
    has_pqc_hybrid_support: bool = False
    automated_cert_rotation: bool = False
    uses_config_driven_crypto: bool = True

class MigrationSimRequest(BaseModel):
    x_shelf_life: int = 10
    y_migration_time: int = 4
    z_crqc_horizon: int = 8
    critical_findings_count: int = 3
    qv_certs_count: int = 2

class MoscaRequest(BaseModel):
    x: int = 10
    y: int = 4
    z: int = 8

class CBOMRequest(BaseModel):
    code_findings: List[Dict[str, Any]] = []
    network_findings: List[Dict[str, Any]] = []
    binary_findings: List[Dict[str, Any]] = []
    target_name: str = "ECDAT-Target"


# ═══════════════════════════════════════════════
# LIVE DISCOVERY & ANALYSIS ENDPOINTS
# ═══════════════════════════════════════════════

@app.post("/api/scan/network")
async def scan_network(req: NetworkScanRequest):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, probe_tls_endpoint, req.target, req.port, 3.0)

    if result.get("status") != "error":
        # Ingest into Knowledge Graph (Module 3)
        service_name = f"Service: {req.target}:{req.port}"
        primitive    = f"Protocol: {result.get('protocol', 'Unknown')} / {result.get('bulk_cipher', result.get('cipher_name', 'Unknown'))}"
        severity     = result.get("hndl_risk", "low").lower()
        kg.add_finding(service_name, primitive, "Network Prober (Live TLS)", severity)
        if result.get("certificate"):
            cert_name  = f"Cert: {result['certificate'].get('subject', 'Unknown')} [{result['certificate'].get('public_key', 'RSA')}]"
            is_expired = result["certificate"].get("expired", False)
            kg.add_finding(service_name, cert_name, "Certificate Verification",
                           "critical" if is_expired else "low")

    return result


@app.post("/api/scan/code")
async def scan_code_endpoint(req: CodeScanRequest):
    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, scan_polyglot_code, req.source_code, req.language)

    # Ingest findings into Knowledge Graph (Module 3)
    target_app = f"App: {req.language.upper()} Code Target"
    for finding in res.get("findings", []):
        primitive = f"Algo: {finding.get('primitive', 'Unknown')} ({req.language})"
        severity  = finding.get("severity", "low").lower()
        kg.add_finding(target_app, primitive, f"AST Scan (Line {finding.get('line')})", severity)

    return res


@app.get("/api/polyglot/samples")
def get_polyglot_samples():
    """Returns curated vulnerable samples for Python, Java, C/C++, Go, and JS."""
    return POLYGLOT_SAMPLES


@app.post("/api/scan/binary")
async def scan_binary_endpoint(req: BinaryScanRequest):
    """
    Module 10: Binary & Firmware Cryptographic Constant / S-Box Scanner.
    Parses compiled hex dumps or synthetic firmware images.
    """
    if req.raw_hex and req.raw_hex.strip():
        try:
            # Clean hex string (remove 0x, spaces, newlines)
            cleaned_hex = req.raw_hex.replace("0x", "").replace(" ", "").replace("\n", "").replace("\r", "")
            raw_bytes = bytes.fromhex(cleaned_hex)
        except Exception:
            raw_bytes = req.raw_hex.encode("utf-8")
    else:
        # Use synthetic compiled ELF firmware binary with embedded S-boxes
        raw_bytes = generate_sample_binary_blob()

    loop = asyncio.get_event_loop()
    res = await loop.run_in_executor(None, scan_binary_data, raw_bytes, req.file_name or "firmware_telemetry.bin")

    # Ingest into Knowledge Graph (Module 3)
    firmware_node = f"Firmware: {req.file_name or 'firmware_telemetry.bin'}"
    for det in res.get("detections", []):
        prim_node = f"Binary Primitive: {det.get('primitive')}"
        sev = det.get("severity", "low").lower()
        kg.add_finding(firmware_node, prim_node, f"Binary Offset {det.get('offset')}", sev)

    return res


@app.post("/api/agility/evaluate")
def evaluate_agility(req: AgilityRequest):
    """Module 7: Cryptographic Agility Index (CAI) evaluation."""
    return calculate_crypto_agility(
        hardcoded_primitives_count=req.hardcoded_primitives_count,
        abstracted_primitives_count=req.abstracted_primitives_count,
        has_provider_abstraction=req.has_provider_abstraction,
        has_pqc_hybrid_support=req.has_pqc_hybrid_support,
        automated_cert_rotation=req.automated_cert_rotation,
        uses_config_driven_crypto=req.uses_config_driven_crypto
    )


@app.post("/api/migration/simulate")
def simulate_migration(req: MigrationSimRequest):
    """Simulates multi-phase PQC Migration Gantt timeline."""
    return simulate_pqc_migration_roadmap(
        x_shelf_life=req.x_shelf_life,
        y_migration_time=req.y_migration_time,
        z_crqc_horizon=req.z_crqc_horizon,
        critical_findings_count=req.critical_findings_count,
        qv_certs_count=req.qv_certs_count
    )


@app.post("/api/risk/mosca")
def evaluate_mosca(req: MoscaRequest):
    return calculate_mosca_risk(req.x, req.y, req.z)


@app.post("/api/export/cbom")
def export_cbom(req: CBOMRequest):
    # Combine code and binary findings for comprehensive CBOM
    all_code = req.code_findings.copy()
    if req.binary_findings:
        for b in req.binary_findings:
            all_code.append({
                "primitive": b.get("primitive", "Unknown"),
                "category": b.get("type", "Binary Constant"),
                "severity": b.get("severity", "MEDIUM"),
                "line": b.get("offset", "0x00"),
                "issue": b.get("description", "")
            })
    return generate_cyclonedx_cbom(all_code, req.network_findings, req.target_name)


# ═══════════════════════════════════════════════
# DEMO & GRAPH STATE ENDPOINTS
# ═══════════════════════════════════════════════

@app.get("/api/demo/overview")
def demo_overview():
    """Live knowledge graph — continuously updated as scans execute."""
    return {"kpis": kg.get_kpis(), "graph": kg.export_for_ui()}


@app.post("/api/demo/network")
def demo_network():
    return DEMO_NETWORK


@app.post("/api/demo/code")
def demo_code():
    return DEMO_CODE


@app.post("/api/demo/mosca")
def demo_mosca(req: MoscaRequest):
    return calculate_mosca_risk(req.x, req.y, req.z)


@app.post("/api/demo/cbom")
def demo_cbom(req: Optional[CBOMRequest] = None):
    findings = (req.code_findings if req else None) or DEMO_CODE["findings"]
    network  = (req.network_findings if req else None) or [DEMO_NETWORK]
    target   = (req.target_name if req else None) or "ECDAT-Demo-SIH26164"
    return generate_cyclonedx_cbom(findings, network, target)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("main:app", host=host, port=port, reload=True)
