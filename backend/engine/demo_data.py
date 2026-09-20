DEMO_OVERVIEW = {
    "kpis": {
        "total_findings": 14,
        "critical": 3,
        "quantum_vulnerable_certs": 2,
        "est_migration_effort": "3-5 Months"
    },
    "graph": {
        "nodes": [
            {"id": "svc_payment", "group": "service", "label": "Payment Gateway", "severity": "low"},
            {"id": "lib_openssl", "group": "library", "label": "OpenSSL 1.0.2", "severity": "critical"},
            {"id": "algo_rc4", "group": "algorithm", "label": "RC4-SHA", "severity": "critical"},
            {"id": "cert_legacy", "group": "certificate", "label": "RSA-1024 Cert", "severity": "high"},
            {"id": "svc_auth", "group": "service", "label": "Auth Service", "severity": "low"},
            {"id": "lib_bouncycastle", "group": "library", "label": "BouncyCastle v1.5", "severity": "medium"},
            {"id": "algo_des", "group": "algorithm", "label": "DES-ECB", "severity": "high"},
            {"id": "algo_aesgcm", "group": "algorithm", "label": "AES-256-GCM", "severity": "low"},
            {"id": "cert_modern", "group": "certificate", "label": "ECDSA-P256 Cert", "severity": "low"}
        ],
        "links": [
            {"source": "svc_payment", "target": "lib_openssl"},
            {"source": "lib_openssl", "target": "algo_rc4"},
            {"source": "lib_openssl", "target": "cert_legacy"},
            {"source": "svc_auth", "target": "lib_bouncycastle"},
            {"source": "lib_bouncycastle", "target": "algo_des"},
            {"source": "lib_bouncycastle", "target": "algo_aesgcm"},
            {"source": "svc_auth", "target": "cert_modern"}
        ]
    }
}

DEMO_NETWORK = {
    "status": "success",
    "target": "demo.internal.corp:443",
    "ip_address": "10.0.5.21",
    "protocol": "TLSv1.0",
    "cipher_name": "TLS_RSA_WITH_RC4_128_SHA",
    "bulk_cipher": "RC4 Stream",
    "key_exchange": "Static RSA (No Forward Secrecy)",
    "secret_bits": 128,
    "symmetric_security": "128-bit (Broken Classically: RFC 7465)",
    "pqc_status": "Legacy Insecure (Zero Quantum Margin)",
    "hndl_risk": "CRITICAL",
    "hndl_rationale": "Static RSA key exchange with obsolete RC4 stream cipher detected. Static RSA lacks Perfect Forward Secrecy, exposing all historical sessions to decryption if the server's private key is factored with Shor's algorithm.",
    "quantum_vulnerable": True,
    "certificate": {
        "subject": "CN=demo.internal.corp",
        "issuer": "CN=Corp Internal CA",
        "public_key": "RSA-1024",
        "valid_from": "2020-01-01 00:00:00 UTC",
        "valid_to": "2022-01-01 00:00:00 UTC",
        "days_remaining": -1600,
        "expired": True,
        "sans": ["demo.internal.corp", "api.internal.corp"],
        "serial_number": "0x4b9a12c4",
        "signature_algorithm": "sha1WithRSAEncryption"
    },
    "recommendations": [
        "Immediately disable TLS 1.0 and RC4.",
        "Upgrade to TLS 1.3 with AES-256-GCM or ChaCha20-Poly1305.",
        "Renew certificate with a minimum of RSA-3072 or ECDSA P-256."
    ]
}

DEMO_CODE = {
    "findings": [
        {
            "line": 42,
            "code": "hash_val = hashlib.md5(password.encode())",
            "primitive": "MD5",
            "category": "Hash Function",
            "severity": "CRITICAL",
            "issue": "MD5 collision vulnerabilities (CWE-327). Cryptographically broken.",
            "nist_recommendation": "Migrate to SHA-256 or SHA-3.",
            "quantum_risk": "Vulnerable to Grover speedup."
        },
        {
            "line": 88,
            "code": "cipher = Crypto.Cipher.DES.new(key, Crypto.Cipher.DES.MODE_ECB)",
            "primitive": "DES-ECB",
            "category": "Symmetric Cipher",
            "severity": "CRITICAL",
            "issue": "56-bit DES is crackable. ECB mode leaks plaintext patterns.",
            "nist_recommendation": "Use AES-256-GCM.",
            "quantum_risk": "Trivially breakable classically."
        },
        {
            "line": 105,
            "code": "rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)",
            "primitive": "RSA-1024",
            "category": "Asymmetric Key",
            "severity": "HIGH",
            "issue": "1024-bit RSA provides insufficient classical security margin.",
            "nist_recommendation": "Upgrade to ML-KEM (FIPS 203).",
            "quantum_risk": "Shor's algorithm breaks this in polynomial time."
        }
    ],
    "remediation": "# ==============================================================================\n# ECDAT REMEDIATED CODE: Enterprise Secure Cryptographic Baseline\n# ==============================================================================\n\nimport os\nimport hashlib\nfrom cryptography.hazmat.primitives.ciphers.aead import AESGCM\n\ndef secure_hash_data(data: bytes) -> str:\n    hasher = hashlib.sha256()\n    hasher.update(data)\n    return hasher.hexdigest()\n\ndef secure_encrypt_payload(plaintext: bytes) -> dict:\n    key = AESGCM.generate_key(bit_length=256)\n    aesgcm = AESGCM(key)\n    nonce = os.urandom(12)\n    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=b\"ECDAT\")\n    return { \"key\": key.hex(), \"nonce\": nonce.hex(), \"ciphertext\": ciphertext.hex() }"
}

DEMO_RISK = {
    "x_shelf_life": 10,
    "y_migration_time": 4,
    "z_crqc_horizon": 8,
    "total_time_needed": 14,
    "deficit_years": 6,
    "is_critical": True,
    "posture_status": "CRITICAL QUANTUM EXPOSURE",
    "posture_badge": "CRITICAL",
    "posture_color": "red",
    "explanation": "Under Mosca's Theorem (X + Y > Z), your data is currently exposed! Required security timeline (14 years) exceeds the estimated CRQC horizon (8 years) by 6 year(s).",
    "nist_mapping": [
        {
            "category": "Asymmetric Key Encapsulation (KEM)",
            "legacy_primitive": "RSA / ECDH",
            "quantum_threat": "Shor's Algorithm",
            "pqc_standard": "FIPS 203: ML-KEM",
            "security_levels": "ML-KEM-512, ML-KEM-768",
            "urgency": "IMMEDIATE"
        },
        {
            "category": "Primary Digital Signatures",
            "legacy_primitive": "RSA / ECDSA",
            "quantum_threat": "Shor's Algorithm",
            "pqc_standard": "FIPS 204: ML-DSA",
            "security_levels": "ML-DSA-44, ML-DSA-65",
            "urgency": "HIGH"
        }
    ]
}
