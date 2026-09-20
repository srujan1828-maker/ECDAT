"""Unit tests for GitHub ingestion, PQC RAG engine, and NVIDIA DeepSeek-R1 integration."""
import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.engine.github_engine import parse_github_url
from backend.engine.rag_engine import rag_engine, PqcRAGEngine
from backend.engine.llm_engine import DeepSeekR1Engine, extract_reasoning_and_code

client = TestClient(app)


def test_github_url_parser():
    # Full standard HTTPS URL
    p1 = parse_github_url("https://github.com/torvalds/linux")
    assert p1["owner"] == "torvalds"
    assert p1["repo"] == "linux"
    assert p1["is_single_file"] is False

    # URL with .git
    p2 = parse_github_url("https://github.com/open-quantum-safe/liboqs.git")
    assert p2["owner"] == "open-quantum-safe"
    assert p2["repo"] == "liboqs"

    # Branch and subfolder
    p3 = parse_github_url("https://github.com/expressjs/express/tree/master/lib")
    assert p3["owner"] == "expressjs"
    assert p3["repo"] == "express"
    assert p3["ref"] == "master"
    assert p3["subpath"] == "lib"

    # Single blob file
    p4 = parse_github_url("https://github.com/pallets/flask/blob/main/src/flask/app.py")
    assert p4["owner"] == "pallets"
    assert p4["repo"] == "flask"
    assert p4["ref"] == "main"
    assert p4["subpath"] == "src/flask/app.py"
    assert p4["is_single_file"] is True

    # Shorthand owner/repo
    p5 = parse_github_url("google/boringssl")
    assert p5["owner"] == "google"
    assert p5["repo"] == "boringssl"

    # Raw URL
    p6 = parse_github_url("https://raw.githubusercontent.com/owner/repo/main/crypto/aes.py")
    assert p6["owner"] == "owner"
    assert p6["repo"] == "repo"
    assert p6["ref"] == "main"
    assert p6["subpath"] == "crypto/aes.py"
    assert p6["is_single_file"] is True


def test_rag_engine_retrieval():
    # Test ML-KEM retrieval
    kem_results = rag_engine.retrieve("ML-KEM-768 hybrid key encapsulation", top_k=2)
    assert len(kem_results) >= 1
    top_doc = kem_results[0]
    assert "FIPS 203" in top_doc["standard"] or "ML-KEM" in top_doc["title"]

    # Test MD5 deprecation retrieval
    md5_results = rag_engine.retrieve("deprecated md5 hash collision vulnerability", top_k=2)
    assert len(md5_results) >= 1
    found_hash_doc = any("MD5" in r["title"] or "Hash" in r["title"] for r in md5_results)
    assert found_hash_doc

    # Test language-specific recipe retrieval
    py_results = rag_engine.retrieve("hashlib sha256 AESGCM", language="python", top_k=2)
    assert len(py_results) >= 1
    assert any(r.get("language") == "python" for r in py_results)


def test_deepseek_r1_reasoning_extraction():
    sample_response = (
        "<think>\n"
        "1. Identified MD5 hash call which violates FIPS 180-4.\n"
        "2. Identified 1024-bit RSA key which is Shor-algorithm vulnerable.\n"
        "3. Remediated MD5 -> SHA-256 and upgraded RSA key size to 3072.\n"
        "</think>\n"
        "Here is the quantum-safe refactored code:\n"
        "```python\n"
        "import hashlib\n"
        "def compute(payload):\n"
        "    return hashlib.sha256(payload).hexdigest()\n"
        "```\n"
        "This adheres to NIST FIPS 203/180-4."
    )

    extracted = extract_reasoning_and_code(sample_response, "python")
    assert "Identified MD5 hash call" in extracted["reasoning"]
    assert "hashlib.sha256(payload)" in extracted["code"]
    assert "Here is the quantum-safe refactored code" in extracted["explanation"]


def test_deepseek_r1_deterministic_fallback():
    # When no NVIDIA API key is provided, should fall back cleanly to AST + RAG
    vulnerable_py = "import hashlib\ndef hash_val(x): return hashlib.md5(x).hexdigest()"
    res = DeepSeekR1Engine.refactor_code(
        file_path="service.py",
        source_code=vulnerable_py,
        language="python",
        api_key="",  # No key
    )
    assert res["success"] is True
    assert res["mode"] == "rag_ast_deterministic"
    assert "sha256" in res["remediated_code"]
    assert len(res["rag_standards"]) >= 1


def test_api_endpoints_rag_and_refactor():
    # Test /api/ai/rag/query
    res = client.post("/api/ai/rag/query", json={"query": "FIPS 203 ML-KEM", "top_k": 2})
    assert res.status_code == 200
    data = res.json()
    assert data["total_results"] >= 1
    assert "ML-KEM" in str(data["results"])

    # Test /api/ai/refactor with fallback
    refactor_res = client.post("/api/ai/refactor", json={
        "file_path": "crypto_test.py",
        "source_code": "import hashlib\ndef test(): return hashlib.md5(b'test').hexdigest()",
        "language": "python",
    })
    assert refactor_res.status_code == 200
    r_data = refactor_res.json()
    assert r_data["success"] is True
    assert "sha256" in r_data["remediated_code"]

    # Test /api/ai/explain
    explain_res = client.post("/api/ai/explain", json={
        "primitive": "RSA-1024",
        "issue": "Factorable via Shor's algorithm on CRQC",
    })
    assert explain_res.status_code == 200
    e_data = explain_res.json()
    assert e_data["success"] is True
