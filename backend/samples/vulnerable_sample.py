"""
SAMPLE VULNERABLE ASSET FOR CRYPTOGRAPHIC DISCOVERY AUDITING
Target: NTRO SIH26164 Demonstration Pipeline
Contains intentional classical cryptographic vulnerabilities:
1. Broken Hashing: MD5 & SHA-1
2. Broken Symmetric Encryption: 56-bit DES in ECB Mode
3. Quantum-Vulnerable Key Exchange: RSA-1024 bit key generation
"""

import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# --- VULNERABILITY 1 & 2: Deprecated / Broken Hashing ---
def generate_insecure_hashes(data: bytes):
    # CRITICAL: MD5 collision susceptibility (RFC 6151)
    md5_digest = hashlib.md5(data).hexdigest()

    # HIGH: SHA-1 collision vulnerabilities (SHAttered)
    sha1_digest = hashlib.sha1(data).hexdigest()

    return {"md5": md5_digest, "sha1": sha1_digest}

# --- VULNERABILITY 3 & 4: Obsolete Symmetric Cipher + ECB Mode ---
def legacy_encrypt_des_ecb(plaintext: bytes, key: bytes):
    # CRITICAL: 56-bit DES is broken by brute force
    # CRITICAL: ECB mode leaks structural patterns of plaintext
    cipher = Cipher(algorithms.DES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

# --- VULNERABILITY 5: Weak Asymmetric RSA Key (1024-bit) ---
def generate_legacy_rsa_key():
    # CRITICAL: RSA 1024-bit is disbarred by NIST SP 800-131A
    # Broken classically by factoring and vulnerable to Shor's algorithm
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    return private_key

if __name__ == "__main__":
    test_data = b"DEFENSE-CLASSIFIED-PAYLOAD-2026"
    print("[*] Generating vulnerable MD5/SHA1...")
    hashes = generate_insecure_hashes(test_data)
    print(hashes)

    print("[*] Generating weak 1024-bit RSA key...")
    key = generate_legacy_rsa_key()
    print(f"[!] Weak RSA Key Generated: {key.key_size} bits")
