import ast
import re
from typing import List, Dict, Any

class CryptoASTVisitor(ast.NodeVisitor):
    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.findings: List[Dict[str, Any]] = []

    def _get_line_snippet(self, lineno: int) -> str:
        if 1 <= lineno <= len(self.source_lines):
            return self.source_lines[lineno - 1].strip()
        return ""

    def visit_Call(self, node: ast.Call):
        func = node.func
        func_name = ""
        attr_chain = []

        curr = func
        while isinstance(curr, ast.Attribute):
            attr_chain.append(curr.attr)
            curr = curr.value
        if isinstance(curr, ast.Name):
            attr_chain.append(curr.id)
        attr_chain.reverse()
        full_call = ".".join(attr_chain)

        lineno = node.lineno
        snippet = self._get_line_snippet(lineno)

        # 1. Deprecated Hashing: MD5
        if full_call in ["hashlib.md5", "md5", "Crypto.Hash.MD5.new", "MD5.new"] or full_call.endswith(".md5"):
            self.findings.append({
                "line": lineno,
                "code": snippet,
                "primitive": "MD5",
                "category": "Hash Function",
                "severity": "CRITICAL",
                "issue": "MD5 has severe collision vulnerabilities (CVE-2004-2761). Cryptographically broken.",
                "nist_recommendation": "Migrate to SHA-256 (FIPS 180-4) or SHA-3 (FIPS 202).",
                "quantum_risk": "Vulnerable to Grover speedup; broken classically."
            })

        # 2. Deprecated Hashing: SHA-1
        elif full_call in ["hashlib.sha1", "sha1", "Crypto.Hash.SHA.new", "SHA.new"] or full_call.endswith(".sha1"):
            self.findings.append({
                "line": lineno,
                "code": snippet,
                "primitive": "SHA-1",
                "category": "Hash Function",
                "severity": "HIGH",
                "issue": "SHA-1 is susceptible to collision attacks (SHAttered, 2017). Disallowed by NIST SP 800-131A.",
                "nist_recommendation": "Migrate to SHA-256, SHA-512, or SHA-3.",
                "quantum_risk": "Broken classically; insufficient collision resistance."
            })

        # 3. Insecure Block Cipher Modes: ECB
        elif full_call in ["modes.ECB", "ECB", "AES.MODE_ECB"] or full_call.endswith(".ECB"):
            self.findings.append({
                "line": lineno,
                "code": snippet,
                "primitive": "ECB Mode",
                "category": "Cipher Mode",
                "severity": "CRITICAL",
                "issue": "Electronic Codebook (ECB) leaks plaintext data patterns because identical blocks produce identical ciphertexts.",
                "nist_recommendation": "Use Authenticated Encryption (AEAD) such as AES-256-GCM (NIST SP 800-38D).",
                "quantum_risk": "Insecure mode regardless of quantum or classical context."
            })

        # 4. Obsolete Symmetric Ciphers: DES / 3DES / ARC4
        elif full_call in ["algorithms.DES", "DES", "Crypto.Cipher.DES.new", "DES.new"]:
            self.findings.append({
                "line": lineno,
                "code": snippet,
                "primitive": "DES",
                "category": "Symmetric Cipher",
                "severity": "CRITICAL",
                "issue": "DES has an obsolete 56-bit key length vulnerable to brute force within hours.",
                "nist_recommendation": "Replace with AES-256 (FIPS 197).",
                "quantum_risk": "Trivially breakable classically; quantumly defenseless."
            })
        elif full_call in ["algorithms.TripleDES", "TripleDES", "DES3", "Crypto.Cipher.DES3.new"]:
            self.findings.append({
                "line": lineno,
                "code": snippet,
                "primitive": "TripleDES",
                "category": "Symmetric Cipher",
                "severity": "HIGH",
                "issue": "Triple-DES (Sweet32 vulnerability) has a 64-bit block size susceptible to collision attacks. Deprecated by NIST.",
                "nist_recommendation": "Replace with AES-256-GCM.",
                "quantum_risk": "Vulnerable to Sweet32 attacks and Grover's search."
            })
        elif full_call in ["algorithms.ARC4", "ARC4", "RC4", "Crypto.Cipher.ARC4.new"]:
            self.findings.append({
                "line": lineno,
                "code": snippet,
                "primitive": "RC4 / ARC4",
                "category": "Stream Cipher",
                "severity": "CRITICAL",
                "issue": "RC4 stream cipher suffers from severe statistical biases in keystream (RFC 7465 prohibitions).",
                "nist_recommendation": "Replace with AES-256-GCM or ChaCha20-Poly1305.",
                "quantum_risk": "Broken classically."
            })

        # 5. Weak / Quantum-Vulnerable Asymmetric Keys (RSA)
        elif "rsa.generate_private_key" in full_call or full_call in ["RSA.generate", "RSA.new"]:
            key_size = None
            for kw in node.keywords:
                if kw.arg in ["key_size", "bits"]:
                    if isinstance(kw.value, ast.Constant):
                        key_size = kw.value.value
            if not key_size and node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, int):
                    key_size = first_arg.value

            if key_size and key_size < 2048:
                self.findings.append({
                    "line": lineno,
                    "code": snippet,
                    "primitive": f"RSA-{key_size}",
                    "category": "Asymmetric Key",
                    "severity": "CRITICAL",
                    "issue": f"RSA key size of {key_size} bits is cryptographically broken and disbarred by NIST.",
                    "nist_recommendation": "Immediate upgrade: RSA >= 3072 bits. Long term: ML-KEM (FIPS 203) / ML-DSA (FIPS 204).",
                    "quantum_risk": "Shor's algorithm completely factors RSA keys in polynomial time."
                })
            elif key_size and key_size <= 2048:
                self.findings.append({
                    "line": lineno,
                    "code": snippet,
                    "primitive": f"RSA-{key_size}",
                    "category": "Asymmetric Key",
                    "severity": "HIGH",
                    "issue": f"RSA-{key_size} offers only ~112 bits of classical security and is completely defenseless against Shor's algorithm.",
                    "nist_recommendation": "Transition to NIST Post-Quantum Cryptography standards: ML-KEM (FIPS 203).",
                    "quantum_risk": "Shor's algorithm will compromise all RSA keys once a CRQC is built."
                })
            else:
                self.findings.append({
                    "line": lineno,
                    "code": snippet,
                    "primitive": f"RSA-{key_size or 'Unknown'}",
                    "category": "Asymmetric Key",
                    "severity": "MEDIUM",
                    "issue": "Classical RSA key exchange/encryption is vulnerable to Harvest Now, Decrypt Later (HNDL) attacks.",
                    "nist_recommendation": "Plan hybrid transition to ML-KEM (FIPS 203) for post-quantum defense.",
                    "quantum_risk": "Shor's algorithm renders classical asymmetric algorithms obsolete."
                })

        self.generic_visit(node)

def scan_code_ast(source_code: str) -> List[Dict[str, Any]]:
    """Parses code with Python AST and inspects cryptographic sinks."""
    lines = source_code.splitlines()
    tree = ast.parse(source_code)
    visitor = CryptoASTVisitor(lines)
    visitor.visit(tree)
    return visitor.findings

def scan_code_regex_fallback(source_code: str) -> List[Dict[str, Any]]:
    """Fallback scanner for partial snippets or syntax-invalid source code."""
    findings = []
    lines = source_code.splitlines()
    
    rules = [
        (r"hashlib\.md5\(", "MD5", "Hash Function", "CRITICAL", "MD5 collision vulnerabilities (broken).", "Upgrade to SHA-256 (FIPS 180-4)."),
        (r"hashlib\.sha1\(", "SHA-1", "Hash Function", "HIGH", "SHA-1 collision vulnerabilities.", "Upgrade to SHA-256."),
        (r"modes\.ECB\(", "ECB Mode", "Cipher Mode", "CRITICAL", "ECB pattern leakage.", "Migrate to AES-256-GCM."),
        (r"algorithms\.DES\(", "DES", "Symmetric Cipher", "CRITICAL", "DES 56-bit key size is crackable.", "Upgrade to AES-256."),
        (r"algorithms\.TripleDES\(", "TripleDES", "Symmetric Cipher", "HIGH", "3DES 64-bit block size vulnerable to Sweet32.", "Upgrade to AES-256-GCM."),
        (r"algorithms\.ARC4\(", "ARC4", "Stream Cipher", "CRITICAL", "RC4 keystream bias flaws.", "Upgrade to AES-256-GCM."),
        (r"key_size\s*=\s*1024", "RSA-1024", "Asymmetric Key", "CRITICAL", "1024-bit RSA is cryptanalytically weak.", "Upgrade to ML-KEM (FIPS 203)."),
        (r"key_size\s*=\s*2048", "RSA-2048", "Asymmetric Key", "HIGH", "RSA-2048 vulnerable to Shor's algorithm.", "Upgrade to ML-KEM (FIPS 203).")
    ]

    for idx, line in enumerate(lines, 1):
        for pattern, primitive, category, severity, issue, rec in rules:
            if re.search(pattern, line):
                findings.append({
                    "line": idx,
                    "code": line.strip(),
                    "primitive": primitive,
                    "category": category,
                    "severity": severity,
                    "issue": issue,
                    "nist_recommendation": rec,
                    "quantum_risk": "Vulnerable to quantum cryptanalysis (Shor or Grover speedup)."
                })
    return findings

def scan_code(source_code: str) -> List[Dict[str, Any]]:
    """
    Main entry point: Scans Python source code using AST with fallback to regex.
    """
    if not source_code or not source_code.strip():
        return []

    try:
        findings = scan_code_ast(source_code)
        return findings
    except SyntaxError:
        # Fallback to regex when code has syntax errors or is an isolated snippet
        return scan_code_regex_fallback(source_code)
    except Exception:
        return scan_code_regex_fallback(source_code)

def generate_remediation_snippet() -> str:
    """
    Returns clean, production-grade drop-in remediation code upgrading MD5 & DES-ECB
    to SHA-256 and AEAD AES-256-GCM with secure key generation.
    """
    return '''# ==============================================================================
# ECDAT REMEDIATED CODE: Enterprise Secure Cryptographic Baseline
# Upgrades:
#   - MD5 / SHA-1  ==> SHA-256 / SHA-3 (FIPS 180-4 / FIPS 202)
#   - DES-ECB      ==> AES-256-GCM (NIST SP 800-38D AEAD)
#   - RSA-1024     ==> Post-Quantum Hybrid / ML-KEM Ready
# ==============================================================================

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 1. REMEDIATED HASHING: Modern SHA-256 (Collision-Resistant)
def secure_hash_data(data: bytes) -> str:
    """Replaces obsolete MD5/SHA-1 with NIST FIPS 180-4 compliant SHA-256."""
    hasher = hashlib.sha256()
    hasher.update(data)
    return hasher.hexdigest()

# 2. REMEDIATED SYMMETRIC ENCRYPTION: AES-256-GCM (Authenticated AEAD)
def secure_encrypt_payload(plaintext: bytes) -> dict:
    """
    Replaces insecure DES/ECB mode with AES-256-GCM.
    - Key Length: 256-bit (Grover Quantum Resistant)
    - Nonce: 96-bit cryptographically random IV
    - Authentication Tag: Built-in 128-bit integrity verification
    """
    # 256-bit key for Grover quantum resistance
    key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(key)
    
    # 96-bit unique IV generated per encryption
    nonce = os.urandom(12)
    
    # Encrypt and automatically append authentication tag
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=b"ECDAT-Protected")
    
    return {
        "key_hex": key.hex(),
        "nonce_hex": nonce.hex(),
        "ciphertext_hex": ciphertext.hex()
    }

def secure_decrypt_payload(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypts and verifies authentication tag. Raises exception if tampered."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=b"ECDAT-Protected")

if __name__ == "__main__":
    secret_payload = b"NTRO-ECDAT-CONFIDENTIAL-TRANSMISSION-2026"
    
    # Test Remediation
    hashed = secure_hash_data(secret_payload)
    print(f"[+] SHA-256 Digest: {hashed}")
    
    enc_data = secure_encrypt_payload(secret_payload)
    print(f"[+] AES-256-GCM Ciphertext: {enc_data['ciphertext_hex'][:32]}... (Secured)")
'''
