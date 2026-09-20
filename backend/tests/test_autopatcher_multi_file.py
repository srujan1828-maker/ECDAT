import pytest
from backend.engine.patch_engine import AutoPatchEngine
from backend.engine.source_scan import scan_sources, normalize_language


def test_normalize_language_cases():
    assert normalize_language("PYTHON") == "python"
    assert normalize_language("Python") == "python"
    assert normalize_language("C_CPP") == "c_cpp"
    assert normalize_language("cpp") == "c_cpp"
    assert normalize_language("JAVASCRIPT") == "javascript"
    assert normalize_language("ts") == "javascript"
    assert normalize_language("GOLANG") == "golang"
    assert normalize_language("go") == "golang"
    assert normalize_language("JAVA") == "java"
    assert normalize_language("BINARY") == "generic"
    assert normalize_language(None, "server.py") == "python"
    assert normalize_language(None, "gateway.c") == "c_cpp"
    assert normalize_language(None, "auth.ts") == "javascript"
    assert normalize_language(None, "README.md") == "generic"


def test_six_file_codebase_auto_patching():
    """Simulate the user's exact multi-file scenario with 6 files across languages."""
    codebase = [
        {
            "path": "services/payment.py",
            "language": "PYTHON",  # Uppercase
            "content": """import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def sign(account_id: str, amount: float):
    payload = f"{account_id}:{amount}".encode()
    tx_hash = hashlib.md5(payload).hexdigest()
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    return tx_hash, key
"""
        },
        {
            "path": "core/gateway.c",
            "language": "C_CPP",  # Uppercase
            "content": """#include <openssl/md5.h>
#include <openssl/des.h>

void process_data(const unsigned char *data, size_t len, unsigned char *out) {
    MD5(data, len, out);
    DES_key_schedule schedule;
    DES_ecb_encrypt((DES_cblock*)data, (DES_cblock*)out, &schedule, 1);
}
"""
        },
        {
            "path": "frontend/auth.js",
            "language": "JAVASCRIPT",  # Uppercase
            "content": """const crypto = require('crypto');
function hashPassword(pwd) {
    return crypto.createHash('md5').update(pwd).digest('hex');
}
function encryptSession(key, data) {
    return crypto.createCipheriv('des-ecb', key, null);
}
"""
        },
        {
            "path": "cloud/service.go",
            "language": "GOLANG",  # Uppercase
            "content": """package main
import "crypto/md5"
import "crypto/des"

func Process(data []byte) {
    h := md5.New()
    h.Write(data)
    _, _ = des.NewCipher([]byte("12345678"))
}
"""
        },
        {
            "path": "enterprise/SecurityProvider.java",
            "language": "JAVA",  # Uppercase
            "content": """import java.security.MessageDigest;
import javax.crypto.Cipher;

public class SecurityProvider {
    public void secure() throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");
    }
}
"""
        },
        {
            "path": "bin/crypto_daemon.elf",
            "language": "BINARY",
            "content": """# Binary Executable Symbols
# MD5_Init
# DES_ecb_encrypt
# RSA_generate_key 1024
"""
        }
    ]

    result = AutoPatchEngine.patch_entire_codebase(codebase)
    summary = result["summary"]

    # Verify 6 files scanned
    assert summary["total_files_scanned"] == 6

    # Verify vulnerable files were identified and patched (> 0)
    assert summary["vulnerable_files_count"] >= 5, f"Expected at least 5 vulnerable files, got {summary['vulnerable_files_count']}"
    assert summary["vulnerabilities_found"] >= 10, f"Expected >= 10 vulnerabilities, got {summary['vulnerabilities_found']}"
    assert summary["vulnerabilities_remediated"] >= 8, f"Expected >= 8 remediated, got {summary['vulnerabilities_remediated']}"
    assert summary["remediation_rate_percent"] > 50.0

    # Verify diffs and patched code are present
    patched_paths = [p["path"] for p in result["patched_files"]]
    assert "services/payment.py" in patched_paths
    assert "core/gateway.c" in patched_paths
    assert "frontend/auth.js" in patched_paths
    assert "cloud/service.go" in patched_paths
    assert "enterprise/SecurityProvider.java" in patched_paths

    # Payment Python check
    py_patch = next(p for p in result["patched_files"] if p["path"] == "services/payment.py")
    assert "hashlib.sha256" in py_patch["patched_code"]
    assert "3072" in py_patch["patched_code"]
    assert py_patch["verification_status"] in ("passed", "static_verified")

    # Gateway C check
    c_patch = next(p for p in result["patched_files"] if p["path"] == "core/gateway.c")
    assert "SHA256(" in c_patch["patched_code"]
    assert "AES_ecb_encrypt" in c_patch["patched_code"]

    # Auth JS check
    js_patch = next(p for p in result["patched_files"] if p["path"] == "frontend/auth.js")
    assert "sha256" in js_patch["patched_code"]
    assert "aes-256-cbc" in js_patch["patched_code"]


def test_file_with_zero_scan_findings_still_patched():
    """Verify that when static scanner doesn't produce findings, AutoPatchEngine still patches it."""
    code = "const token = createHash('md5').update(str).digest('hex');"
    # Even if scanned as generic or custom
    patch = AutoPatchEngine.create_patch(code, "util.ts", "typescript")
    assert patch is not None
    assert "sha256" in patch.patched_code

    # Batch test
    files = [{"path": "util.ts", "content": code, "language": "typescript"}]
    res = AutoPatchEngine.patch_entire_codebase(files)
    assert res["summary"]["vulnerable_files_count"] == 1
    assert res["summary"]["vulnerabilities_remediated"] >= 1


def test_javascript_patch_uses_honest_static_verification_without_node(monkeypatch):
    source = "const crypto = require('crypto'); crypto.createHash('md5').update('x').digest('hex');"
    patch = AutoPatchEngine.create_patch(source, "security.js", "javascript")
    assert patch is not None

    def missing_node(*args, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", "node")

    monkeypatch.setattr("backend.engine.patch_engine.subprocess.run", missing_node)
    verified = AutoPatchEngine.run_regression_test(patch)

    assert verified.verification_status == "static_verified"
    assert "post-patch static rescan verified fewer" in verified.test_output
    assert "passed" not in verified.test_output.lower()
