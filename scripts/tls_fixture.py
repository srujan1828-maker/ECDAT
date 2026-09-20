"""Owned HTTPS target for the production-stack regression check."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
import socket
import ssl
import threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@contextmanager
def https_fixture(directory):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(2).not_valid_before(datetime.now(timezone.utc)-timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc)+timedelta(days=1)).sign(key, hashes.SHA256()))
    cert_file, key_file = Path(directory)/'fixture.crt', Path(directory)/'fixture.key'
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert_file, key_file)
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.1)
    done = threading.Event()
    def serve():
        while not done.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            conn.settimeout(.5)
            try:
                with context.wrap_socket(conn, server_side=True) as secure:
                    if secure.recv(4096).startswith(b'HEAD / HTTP/1.1'):
                        secure.sendall(b'HTTP/1.1 200 OK\r\nServer: ec-test\r\nX-Vercel-Id: fixture\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            except OSError:
                conn.close()
    thread = threading.Thread(target=serve, daemon=True); thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        done.set(); thread.join(2); listener.close()
