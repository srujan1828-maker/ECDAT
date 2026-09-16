"""Measured TLS observations; never infer negotiated cryptography from a hostname."""
import ipaddress
import json
import subprocess
import sys
import os
import socket
import ssl
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit
from .pqc_probe import probe_pqc, pqc_label
from cryptography import x509
from cryptography.hazmat.primitives import hashes


def clean_target_host(target):
    target = target.strip()
    if not target:
        raise ValueError('Target is required')
    parsed = urlsplit(target if '://' in target else '//' + target)
    if parsed.scheme and parsed.scheme not in ('https', 'http'):
        raise ValueError('Only hostnames or HTTP(S) URLs are supported')
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError('Invalid target host')
    host = parsed.hostname.encode('idna').decode('ascii')
    return host, parsed.port or 443


def resolve_target(host, port):
    # Run DNS in a bounded child process: socket timeouts do not bound getaddrinfo.
    try:
        dns = subprocess.run([sys.executable, '-c',
            'import socket,json,sys; print(json.dumps(socket.getaddrinfo(sys.argv[1], int(sys.argv[2]), type=socket.SOCK_STREAM)))',
            host, str(port)], capture_output=True, text=True, timeout=3, check=True)
        addresses = json.loads(dns.stdout)
    except (subprocess.SubprocessError, ValueError) as exc:
        raise ValueError('DNS resolution failed or exceeded 3 seconds') from exc
    allow = [ipaddress.ip_network(x.strip()) for x in os.getenv('ECDAT_ALLOWED_CIDRS', '').split(',') if x.strip()]
    approved = []
    for family, kind, proto, _, sockaddr in addresses:
        sockaddr = tuple(sockaddr)
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global and not any(address in network for network in allow):
            raise ValueError('Private/local targets require an explicit ECDAT_ALLOWED_CIDRS allowlist')
        if (family, sockaddr) not in approved:
            approved.append((family, sockaddr))
    if not approved:
        raise ValueError('Target resolved to no usable addresses')
    return approved[0]


def _handshake(host, address, context, timeout):
    family, sockaddr = address
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(timeout)
    try:
        raw.connect(sockaddr)
        return context.wrap_socket(raw, server_hostname=host)
    except Exception:
        raw.close()
        raise


def _context(verify=False, version=None, cipher=None):
    ctx = ssl.create_default_context() if verify else ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        ctx.set_ciphers('ALL:@SECLEVEL=0')
    if version is not None:
        ctx.minimum_version = ctx.maximum_version = version
        ctx.set_ciphers((cipher or 'ALL') + ':@SECLEVEL=0')
    return ctx


def probe_tls_endpoint(host, port=443, timeout=2.0):
    clean_host, parsed_port = clean_target_host(host)
    actual_port = port if port != 443 else parsed_port
    if not 1 <= actual_port <= 65535:
        raise ValueError('Port must be between 1 and 65535')
    started = time.monotonic()
    address = resolve_target(clean_host, actual_port)
    deadline = started + 25
    result = {'status': 'error', 'target': f'{clean_host}:{actual_port}', 'host': clean_host,
              'port': actual_port, 'ip_address': address[1][0], 'timestamp': datetime.now(timezone.utc).isoformat(),
              'protocol': 'Unknown', 'cipher_name': 'Unknown', 'bulk_cipher': 'Unknown',
              'secret_bits': 0, 'key_exchange': 'Unknown (negotiated group not exposed by this engine)',
              'pqc_status': 'Unknown / not measured', 'quantum_vulnerable': None,
              'hndl_risk': 'UNKNOWN', 'hndl_rationale': 'PQC/HNDL status requires measured key exchange and data-retention context.',
              'symmetric_security': 'Unknown', 'certificate': {}, 'recommendations': [],
              'protocol_tests': [], 'cipher_tests': []}
    try:
        with _handshake(clean_host, address, _context(), timeout) as conn:
            cipher = conn.cipher()
            result.update(protocol=conn.version(), cipher_name=cipher[0], bulk_cipher=cipher[0], secret_bits=cipher[2], symmetric_security=f'{cipher[2]}-bit negotiated cipher')
            cert = x509.load_der_x509_certificate(conn.getpeercert(binary_form=True))
            key = cert.public_key()
            key_type = type(key).__name__
            if hasattr(key, 'key_size'):
                key_type += f'-{key.key_size}'
            expires = cert.not_valid_after_utc
            now = datetime.now(timezone.utc)
            try:
                sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                sans = []
            result['certificate'] = {'subject': cert.subject.rfc4514_string(), 'issuer': cert.issuer.rfc4514_string(),
                'public_key': key_type, 'valid_from': cert.not_valid_before_utc.isoformat(), 'valid_to': expires.isoformat(),
                'days_remaining': (expires - now).days, 'expired': expires < now, 'sans': sans,
                'serial_number': hex(cert.serial_number), 'signature_algorithm': cert.signature_algorithm_oid.dotted_string,
                'sha256': cert.fingerprint(hashes.SHA256()).hex()}
        result['status'] = 'success'
    except (OSError, ValueError) as exc:
        result['error'] = f'TLS collection failed: {exc}'
        return result
    try:
        with _handshake(clean_host, address, _context(verify=True), timeout):
            result['certificate']['trust_validated'] = True
    except (OSError, ValueError) as exc:
        result['certificate'].update(trust_validated=False, verification_error=str(exc))
    for version in (ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
        if time.monotonic() >= deadline:
            result['protocol_tests'].append({'version': version.name, 'status': 'not_tested', 'reason': 'Scan deadline'})
            continue
        try:
            with _handshake(clean_host, address, _context(version=version), min(timeout, max(0.1, deadline-time.monotonic()))) as conn:
                result['protocol_tests'].append({'version': version.name, 'status': 'supported', 'negotiated': conn.version(), 'cipher': conn.cipher()[0]})
        except (OSError, ValueError) as exc:
            result['protocol_tests'].append({'version': version.name, 'status': 'not_negotiated', 'reason': str(exc)})
    # A bounded candidate list, not a claim of exhaustive enumeration.
    for cipher in ('ECDHE-RSA-AES256-GCM-SHA384', 'ECDHE-RSA-AES128-GCM-SHA256', 'AES128-SHA', 'DES-CBC3-SHA'):
        if time.monotonic() >= deadline:
            result['cipher_tests'].append({'cipher': cipher, 'status': 'not_tested'})
            continue
        try:
            with _handshake(clean_host, address, _context(version=ssl.TLSVersion.TLSv1_2, cipher=cipher), min(timeout, max(0.1, deadline-time.monotonic()))) as conn:
                result['cipher_tests'].append({'cipher': cipher, 'status': 'supported', 'negotiated': conn.cipher()[0]})
        except (OSError, ValueError) as exc:
            result['cipher_tests'].append({'cipher': cipher, 'status': 'not_negotiated', 'reason': str(exc)})
    result['post_quantum'] = probe_pqc(clean_host, address[1][0], actual_port)
    result['pqc_status'] = pqc_label(result['post_quantum'])
    result['coverage'] = {'addresses_tested': 1, 'protocol_candidates': 4, 'cipher_candidates': 4,
                          'limitations': ['Cipher list is bounded, not exhaustive.', 'PQC capability is tested in separate TLS 1.3 handshakes; no revocation or full-chain PQ signature check.', 'Failed negotiation may reflect local OpenSSL capabilities.']}
    return result
