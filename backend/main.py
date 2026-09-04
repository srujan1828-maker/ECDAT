from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import asyncio

from engine.network_prober import probe_tls_endpoint
from engine.ast_scanner import scan_code, generate_remediation_snippet
from engine.quantum_risk import calculate_mosca_risk
from engine.cbom_generator import generate_cyclonedx_cbom
from engine.demo_data import DEMO_NETWORK, DEMO_CODE
from engine.knowledge_graph import kg

app = FastAPI(
    title="ECDAT API",
    description="Enterprise Cryptographic Discovery & Analysis Tool — SIH26164 (NTRO)",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000", "http://127.0.0.1:3000",
        "http://localhost:3001", "http://127.0.0.1:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request models ─────────────────────────────────────────────────────────────

class NetworkScanRequest(BaseModel):
    target: str
    port: int = 443

class CodeScanRequest(BaseModel):
    source_code: str

class MoscaRequest(BaseModel):
    x: int = 10
    y: int = 4
    z: int = 8

class CBOMRequest(BaseModel):
    code_findings: List[Dict[str, Any]] = []
    network_findings: List[Dict[str, Any]] = []
    target_name: str = "ECDAT-Target"


# ═══════════════════════════════════════════════
# LIVE SCAN ENDPOINTS
# ═══════════════════════════════════════════════

@app.post("/api/scan/network")
async def scan_network(req: NetworkScanRequest):
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, probe_tls_endpoint, req.target, req.port, 3.0)

    if result.get("status") != "error":
        # Update Knowledge Graph (Module 3 — continuous ingestion)
        service_name = f"Service: {req.target}:{req.port}"
        primitive    = f"Protocol: {result.get('protocol', 'Unknown')} / {result.get('cipher_name', 'Unknown')}"
        severity     = result.get("hndl_risk", "low").lower()
        kg.add_finding(service_name, primitive, "Network Prober (Live TLS)", severity)
        if result.get("certificate"):
            cert_name  = f"Cert: {result['certificate'].get('subject', 'Unknown')}"
            is_expired = result["certificate"].get("expired", False)
            kg.add_finding(service_name, cert_name, "Certificate Verification",
                           "critical" if is_expired else "low")

    return result


@app.post("/api/scan/code")
async def scan_code_endpoint(req: CodeScanRequest):
    loop = asyncio.get_event_loop()
    findings = await loop.run_in_executor(None, scan_code, req.source_code)

    # Update Knowledge Graph (Module 3)
    for finding in findings:
        primitive = f"Algo: {finding.get('primitive', 'Unknown')}"
        severity  = finding.get("severity", "low").lower()
        kg.add_finding("App: Scanned Target", primitive,
                       f"AST Scan (Line {finding.get('line')})", severity)

    return {"findings": findings, "remediation": generate_remediation_snippet()}


@app.post("/api/risk/mosca")
def evaluate_mosca(req: MoscaRequest):
    return calculate_mosca_risk(req.x, req.y, req.z)


@app.post("/api/export/cbom")
def export_cbom(req: CBOMRequest):
    return generate_cyclonedx_cbom(req.code_findings, req.network_findings, req.target_name)


# ═══════════════════════════════════════════════
# DEMO ENDPOINTS
# ═══════════════════════════════════════════════

@app.get("/api/demo/overview")
def demo_overview():
    """Live knowledge graph — grows as real scans are run in the session."""
    return {"kpis": kg.get_kpis(), "graph": kg.export_for_ui()}


@app.post("/api/demo/network")
def demo_network():
    return DEMO_NETWORK


@app.post("/api/demo/code")
def demo_code():
    return DEMO_CODE


@app.post("/api/demo/mosca")
def demo_mosca(req: MoscaRequest):
    """
    Runs the REAL Mosca's theorem computation with the slider values from the UI.
    In demo mode, the computation is identical to live — just without the network call.
    """
    return calculate_mosca_risk(req.x, req.y, req.z)


@app.post("/api/demo/cbom")
def demo_cbom(req: Optional[CBOMRequest] = None):
    findings = (req.code_findings if req else None) or DEMO_CODE["findings"]
    network  = (req.network_findings if req else None) or [DEMO_NETWORK]
    target   = (req.target_name if req else None) or "ECDAT-Demo-SIH26164"
    return generate_cyclonedx_cbom(findings, network, target)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
