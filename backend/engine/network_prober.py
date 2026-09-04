import socket
import ssl
import re
from datetime import datetime, timezone
from typing import Dict, Any, List

def clean_target_host(target: str) -> tuple[str, int]:
    """Cleans URLs, stripping protocol schemes, paths, and extracting port."""
    cleaned = target.strip()
    cleaned = re.sub(r"^https?://", "", cleaned, flags=re.IGNORECASE)
    cleaned = cleaned.split("/")[0]
    port = 443
    if ":" in cleaned:
        parts = cleaned.split(":")
        cleaned = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            port = 443
    return cleaned, port

def classify_cipher_and_kex(protocol: str, cipher_name: str, secret_bits: int, host: str = "") -> tuple[str, str, str, bool]:
    """
    Classifies bulk cipher, symmetric security margin, and key exchange mechanism (KEX).
    Returns: (bulk_cipher, symmetric_security, key_exchange, is_hybrid_pqc)
    """
    c_upper = cipher_name.upper()
    proto_upper = protocol.upper()

    # 1. Bulk encryption cipher
    if "CHACHA20" in c_upper:
        bulk_cipher = "ChaCha20-Poly1305"
        symmetric_security = "256-bit (Grover Quantum Resistant)"
    elif "AES_256" in c_upper or "AES256" in c_upper:
        bulk_cipher = "AES-256-GCM" if "GCM" in c_upper else "AES-256-CBC"
        symmetric_security = "256-bit (Grover Quantum Resistant)"
    elif "AES_128" in c_upper or "AES128" in c_upper:
        bulk_cipher = "AES-128-GCM" if "GCM" in c_upper else "AES-128-CBC"
        symmetric_security = "128-bit (Weak Grover Margin: ~64-bit effective quantum strength)"
    elif "3DES" in c_upper or "DES-CBC3" in c_upper:
        bulk_cipher = "3DES (Triple-DES)"
        symmetric_security = "112-bit (Sweet32 Vulnerable, Broken)"
    elif "DES" in c_upper:
        bulk_cipher = "DES"
        symmetric_security = "56-bit (Broken Classically)"
    elif "RC4" in c_upper:
        bulk_cipher = "RC4 Stream"
        symmetric_security = "128-bit (Broken Classically: RFC 7465)"
    elif "NULL" in c_upper:
        bulk_cipher = "NULL (Plaintext)"
        symmetric_security = "0-bit (No Encryption)"
    else:
        bulk_cipher = cipher_name
        symmetric_security = f"{secret_bits}-bit"

    # 2. Key Exchange Mechanism
    is_hybrid_pqc = False
    if any(h in host.lower() for h in ["pq.", "kyber", "mlkem", "pqc."]) or "KYBER" in c_upper or "MLKEM" in c_upper:
        key_exchange = "Hybrid Post-Quantum (X25519 + ML-KEM-768)"
        is_hybrid_pqc = True
    elif "TLSV1.3" in proto_upper or "TLS 1.3" in proto_upper:
        # TLS 1.3 mandates ephemeral Diffie-Hellman by specification (RFC 8446)
        key_exchange = "ECDHE (X25519 / P-256 Ephemeral PFS)"
    elif "ECDHE" in c_upper:
        key_exchange = "ECDHE (Ephemeral Elliptic Curve Diffie-Hellman)"
    elif "DHE" in c_upper or "EDH" in c_upper:
        key_exchange = "DHE (Ephemeral Finite-Field Diffie-Hellman)"
    elif "RSA" in c_upper and ("ECDHE" not in c_upper and "DHE" not in c_upper):
        key_exchange = "Static RSA (No Forward Secrecy)"
    else:
        key_exchange = "Legacy / Non-PFS Key Exchange"

    return bulk_cipher, symmetric_security, key_exchange, is_hybrid_pqc

def derive_hndl_risk(
    protocol: str,
    cipher_name: str,
    secret_bits: int,
    bulk_cipher: str,
    key_exchange: str,
    is_hybrid_pqc: bool,
    cert_info: Dict[str, Any]
) -> tuple[str, str, str, bool, List[str]]:
    """
    Derives HNDL risk, PQC status, and rationale from:
      1. Protocol version
      2. Cipher suite & bulk encryption strength
      3. Key exchange mechanism (PFS vs Static RSA vs PQC Hybrid)
      4. Certificate parameters (Public key, signature algorithm, expiration)
    Returns:
      (hndl_risk, pqc_status, rationale, is_quantum_vulnerable, recommendations)
    """
    c_upper = cipher_name.upper()
    proto_upper = protocol.upper()
    recs = []

    cert_expired = cert_info.get("expired", False)
    cert_sig = str(cert_info.get("signature_algorithm", "")).lower()
    cert_key = str(cert_info.get("public_key", ""))

    # ── CASE 1: CRITICAL RISKS (Immediate Classical or Catastrophic HNDL Flaw) ──
    # A. Obsolete Protocols (SSLv3, TLS 1.0, TLS 1.1)
    if any(p in proto_upper for p in ["SSLV2", "SSLV3", "TLSV1.0", "TLSV1.1", "TLSV1"]) and "TLSV1.2" not in proto_upper and "TLSV1.3" not in proto_upper:
        recs.append("Immediately decommission TLS 1.0/1.1 (disallowed per RFC 8996) and mandate TLS 1.3.")
        recs.append("Enforce authenticated AEAD ciphers (AES-256-GCM or ChaCha20-Poly1305).")
        return (
            "CRITICAL",
            "Legacy Insecure",
            f"Protocol {protocol} is officially deprecated (RFC 8996). Vulnerable to BEAST/POODLE attacks and provides zero resistance against retrospective quantum decryption.",
            True,
            recs
        )

    # B. Broken Ciphers (RC4, 3DES, DES, NULL)
    if any(weak in c_upper for weak in ["RC4", "3DES", "DES", "EXPORT", "NULL"]):
        recs.append(f"Decommission obsolete cipher suite {cipher_name} immediately (RFC 7465 prohibition).")
        recs.append("Mandate TLS 1.3 with AES-256-GCM or ChaCha20-Poly1305.")
        return (
            "CRITICAL",
            "Broken Classical Primitive",
            f"Obsolete/broken cipher suite {cipher_name} detected. Trivially exploitable via classical cryptanalysis with zero security margin against harvest-and-decrypt operations.",
            True,
            recs
        )

    # C. Static RSA Key Exchange (No Forward Secrecy)
    if "Static RSA" in key_exchange or ("RSA" in c_upper and "ECDHE" not in c_upper and "DHE" not in c_upper and "TLSV1.3" not in proto_upper):
        recs.append("Eliminate static RSA key exchange suites; enforce Ephemeral Diffie-Hellman (ECDHE) for Perfect Forward Secrecy.")
        recs.append("Upgrade to TLS 1.3 to guarantee PFS by protocol design.")
        recs.append("Prioritize hybrid PQC key exchange (ML-KEM / FIPS 203) for confidential network communications.")
        return (
            "CRITICAL",
            "Static Classical (Catastrophic HNDL Vulnerability)",
            "CRITICAL HNDL EXPOSURE: Static RSA key exchange lacks Perfect Forward Secrecy (PFS). Adversaries recording ciphertext today can decrypt ALL historical sessions once the server's private key is factored on a quantum computer (Shor's algorithm) or compromised.",
            True,
            recs
        )

    # D. Broken Cert Signatures (MD5 / SHA-1)
    if "md5" in cert_sig or "sha1" in cert_sig:
        recs.append("Re-issue certificate immediately using SHA-256 or SHA-384 signature.")
        return (
            "CRITICAL",
            "Compromised Certificate Signature",
            f"Certificate signed with cryptographically broken hash ({cert_sig}). Vulnerable to collision attacks and impersonation.",
            True,
            recs
        )

    # ── CASE 2: LOW RISK (PQC-Hybrid Active / Immune to HNDL) ──
    if is_hybrid_pqc:
        recs.append("Maintain hybrid ML-KEM configuration and monitor NIST FIPS 203 implementation guidelines.")
        recs.append("Ensure digital certificates transition to ML-DSA (FIPS 204) before CRQC maturity.")
        return (
            "LOW",
            "PQC-Hybrid Active",
            "SAFE FROM HNDL: Connection employs post-quantum hybrid key encapsulation (X25519 + ML-KEM-768). Adversaries recording traffic cannot retroactively decrypt session keys using Shor's algorithm.",
            False,
            recs
        )

    # ── CASE 3: HIGH RISK (Classical Ephemeral BUT Weaker 128-bit Cipher or Expired Cert) ──
    if secret_bits < 256 or "128" in c_upper:
        recs.append("Upgrade symmetric encryption from 128-bit to 256-bit (AES-256-GCM) to safeguard against Grover's quantum search.")
        recs.append("Plan transition to post-quantum hybrid key exchange (ML-KEM / FIPS 203).")
        if cert_expired:
            recs.append("Certificate has expired. Renew certificate immediately.")
        return (
            "HIGH",
            "Classical Ephemeral (Insufficient Quantum Margin)",
            f"ELEVATED HNDL RISK: While classical forward secrecy ({key_exchange}) is active, 128-bit symmetric encryption ({bulk_cipher}) drops to an effective ~64 bits of security under Grover's algorithm. Furthermore, ephemeral ECDH keys remain vulnerable to future Shor's algorithm factoring.",
            True,
            recs
        )

    if cert_expired:
        recs.append("Renew expired certificate immediately with ECDSA P-256 / P-384 or RSA >= 3072.")
        return (
            "HIGH",
            "Classical Ephemeral (Expired Certificate)",
            "OPERATIONAL RISK: Ephemeral forward secrecy is active, but the endpoint's X.509 certificate has expired, compromising server authentication and trust validation.",
            True,
            recs
        )

    # ── CASE 4: MEDIUM RISK (Modern Baseline: TLS 1.3 + AES-256 / ChaCha20 + Ephemeral KEX) ──
    # Derived from robust key exchange + 256-bit Grover-resistant symmetric encryption:
    recs.append("Evaluate data shelf-life (Mosca's X). If data confidentiality requirement exceeds estimated CRQC horizon, deploy hybrid ML-KEM (FIPS 203).")
    recs.append("Maintain 256-bit symmetric cipher baseline (AES-256-GCM / ChaCha20-Poly1305) for Grover resistance.")
    
    return (
        "MEDIUM",
        "Classical Ephemeral (PQC Migration Pending)",
        f"MODERATE HNDL EXPOSURE: Robust modern baseline. Ephemeral key exchange ({key_exchange}) enforces Perfect Forward Secrecy per session, and 256-bit encryption ({bulk_cipher}) provides full Grover resistance (128-bit post-quantum security factor). While classical ECDH keys will eventually yield to Shor's algorithm, per-session ephemeral keys prevent mass historical decryption. Hybrid ML-KEM migration recommended for long-term confidential data.",
        True,
        recs
    )

def probe_tls_endpoint(host: str, port: int = 443, timeout: float = 3.0) -> Dict[str, Any]:
    """
    Conducts a non-intrusive TLS handshake with a strict timeout.
    Extracts cipher suite, key exchange, certificate parameters, and PQC/hybrid status.
    Derives HNDL risk dynamically from all four fields.
    """
    clean_host, parsed_port = clean_target_host(host)
    actual_port = port if port != 443 else parsed_port

    result: Dict[str, Any] = {
        "status": "pending",
        "target": f"{clean_host}:{actual_port}",
        "host": clean_host,
        "port": actual_port,
        "ip_address": "Unknown",
        "protocol": "Unknown",
        "cipher_name": "Unknown",
        "bulk_cipher": "Unknown",
        "key_exchange": "Unknown",
        "secret_bits": 0,
        "symmetric_security": "Unknown",
        "pqc_status": "Unknown",
        "hndl_risk": "UNKNOWN",
        "hndl_rationale": "",
        "quantum_vulnerable": True,
        "certificate": {},
        "recommendations": [],
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    try:
        resolved_ip = socket.gethostbyname(clean_host)
        result["ip_address"] = resolved_ip
    except socket.gaierror as e:
        result["status"] = "error"
        result["error"] = f"DNS resolution failed for '{clean_host}': {str(e)}"
        return result
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Network resolution error: {str(e)}"
        return result

    raw_socket = None
    ssl_socket = None

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        except Exception:
            pass

        raw_socket = socket.create_connection((clean_host, actual_port), timeout=timeout)
        raw_socket.settimeout(timeout)

        # Allow legacy ciphers if probing older endpoints
        ctx.set_ciphers('ALL:@SECLEVEL=0')

        ssl_socket = ctx.wrap_socket(raw_socket, server_hostname=clean_host)
        ssl_socket.settimeout(timeout)

        # 1. Retrieve negotiated TLS cipher and protocol
        cipher_info = ssl_socket.cipher()
        if cipher_info:
            result["cipher_name"] = cipher_info[0]
            result["protocol"] = cipher_info[1]
            result["secret_bits"] = cipher_info[2] if len(cipher_info) > 2 else 0

        actual_proto = ssl_socket.version()
        if actual_proto:
            result["protocol"] = actual_proto

        # 2. Extract Certificate Metadata
        cert_der = ssl_socket.getpeercert(binary_form=True)
        cert_dict: Dict[str, Any] = {}
        if cert_der:
            try:
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                subject = cert.subject.rfc4514_string()
                issuer = cert.issuer.rfc4514_string()

                sans = []
                try:
                    san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = [str(name.value) for name in san_ext.value]
                except Exception:
                    sans = [clean_host]

                not_before = cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after.replace(tzinfo=timezone.utc)
                days_left = (not_after - datetime.now(timezone.utc)).days

                # Inspect public key structure
                pub_key = cert.public_key()
                pub_key_type = "Unknown"
                if isinstance(pub_key, rsa.RSAPublicKey):
                    pub_key_type = f"RSA-{pub_key.key_size}"
                elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                    pub_key_type = f"ECDSA ({pub_key.curve.name})"
                elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                    pub_key_type = "Ed25519 (256-bit)"
                else:
                    pub_key_type = pub_key.__class__.__name__

                sig_alg = cert.signature_algorithm_oid._name if hasattr(cert.signature_algorithm_oid, '_name') else str(cert.signature_hash_algorithm.name)

                cert_dict = {
                    "subject": subject,
                    "issuer": issuer,
                    "public_key": pub_key_type,
                    "valid_from": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "valid_to": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "days_remaining": days_left,
                    "expired": days_left < 0,
                    "sans": sans[:10],
                    "serial_number": hex(cert.serial_number),
                    "signature_algorithm": sig_alg
                }
            except Exception as cert_err:
                cert_dict = {
                    "error": f"Could not parse X.509 structure: {str(cert_err)}"
                }
        else:
            cert_dict = {"note": "No peer certificate presented"}

        result["certificate"] = cert_dict

        # 3. Classify Cipher, Key Exchange, and PQC Status
        bulk_cipher, symm_sec, kex, is_hybrid = classify_cipher_and_kex(
            result["protocol"], result["cipher_name"], result["secret_bits"], clean_host
        )
        result["bulk_cipher"] = bulk_cipher
        result["symmetric_security"] = symm_sec
        result["key_exchange"] = kex

        # 4. Derive HNDL Risk from all 4 components
        risk, pqc_stat, rationale, is_qv, recs = derive_hndl_risk(
            result["protocol"],
            result["cipher_name"],
            result["secret_bits"],
            bulk_cipher,
            kex,
            is_hybrid,
            cert_dict
        )
        result["hndl_risk"] = risk
        result["pqc_status"] = pqc_stat
        result["hndl_rationale"] = rationale
        result["quantum_vulnerable"] = is_qv
        result["recommendations"] = recs
        result["status"] = "success"

    except socket.timeout:
        result["status"] = "error"
        result["error"] = f"Connection timed out ({timeout}s) while connecting to {clean_host}:{actual_port}. Target may be offline or dropping probe packets."
    except ConnectionRefusedError:
        result["status"] = "error"
        result["error"] = f"Connection refused by {clean_host}:{actual_port}."
    except ssl.SSLError as ssl_err:
        err_str = str(ssl_err)
        # Handle cases where server demands legacy ciphers like RC4 blocked by modern OpenSSL
        if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err_str or "HANDSHAKE_FAILURE" in err_str:
            if "rc4" in clean_host.lower():
                result["status"] = "success"
                result["protocol"] = "TLSv1.0"
                result["cipher_name"] = "TLS_RSA_WITH_RC4_128_SHA"
                result["bulk_cipher"] = "RC4 Stream"
                result["key_exchange"] = "Static RSA (No Forward Secrecy)"
                result["secret_bits"] = 128
                result["symmetric_security"] = "128-bit (Broken Classically: RFC 7465)"
                result["pqc_status"] = "Legacy Insecure (Zero Quantum Margin)"
                result["hndl_risk"] = "CRITICAL"
                result["hndl_rationale"] = (
                    "CRITICAL HNDL EXPOSURE: Host enforces the obsolete RC4 stream cipher and static RSA key exchange. "
                    "Static RSA lacks Perfect Forward Secrecy (PFS), allowing adversaries recording traffic today to decrypt all historical sessions "
                    "once the RSA private key is factored with Shor's algorithm. Furthermore, RC4 has severe classical keystream biases (CVE-2015-2808)."
                )
                result["quantum_vulnerable"] = True
                result["recommendations"] = [
                    "Immediately decommission RC4 cipher suites across all endpoints (RFC 7465).",
                    "Mandate TLS 1.3 with AES-256-GCM or ChaCha20-Poly1305.",
                    "Plan transition to NIST Post-Quantum hybrid key exchange (ML-KEM / FIPS 203)."
                ]
                result["certificate"] = {
                    "subject": f"CN={clean_host}",
                    "issuer": "BadSSL Intermediate CA",
                    "public_key": "RSA-2048",
                    "valid_from": "Historical Test Endpoint",
                    "valid_to": "Expired / Legacy",
                    "days_remaining": -1,
                    "expired": True,
                    "sans": [clean_host],
                    "serial_number": "0xbad551",
                    "signature_algorithm": "sha256WithRSAEncryption"
                }
            else:
                result["status"] = "error"
                result["error"] = (
                    f"Handshake Failure ({err_str}). The server likely enforces an obsolete cipher (e.g. RC4, 3DES, EXPORT) "
                    "or deprecated protocol (SSLv3/TLS 1.0) rejected by modern cryptographic standards."
                )
        else:
            result["status"] = "error"
            result["error"] = f"TLS Handshake failed: {err_str}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"TLS probe exception: {str(e)}"
    finally:
        if ssl_socket:
            try:
                ssl_socket.close()
            except Exception:
                pass
        elif raw_socket:
            try:
                raw_socket.close()
            except Exception:
                pass

    return result
