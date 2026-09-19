"""Post-Quantum Cryptography RAG (Retrieval-Augmented Generation) Engine.

Lightweight, in-memory, dependency-free semantic knowledge retriever grounded in:
- NIST FIPS 203 (ML-KEM Module-Lattice Key Encapsulation Mechanism)
- NIST FIPS 204 (ML-DSA Module-Lattice Digital Signature Algorithm)
- NIST FIPS 205 (SLH-DSA Stateless Hash-Based Digital Signature Algorithm)
- NSA CNSA 2.0 Timelines and Post-Quantum Mandates
- RFC 6151, RFC 6194, RFC 7465, and NIST SP 800-131A Cryptographic Deprecations
- Polyglot Remediation Code Recipes for Python, Node.js, Go, Java, and C/C++
"""
from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class RAGDocument:
    def __init__(
        self,
        doc_id: str,
        title: str,
        standard: str,
        category: str,
        tags: List[str],
        content: str,
        remediation_snippet: Optional[str] = None,
        language: Optional[str] = None,
    ):
        self.doc_id = doc_id
        self.title = title
        self.standard = standard
        self.category = category  # e.g. "PQC_KEM", "PQC_SIGNATURE", "SYMMETRIC", "HASH", "REGULATORY"
        self.tags = [t.lower() for t in tags]
        self.content = content.strip()
        self.remediation_snippet = remediation_snippet.strip() if remediation_snippet else None
        self.language = language

    def to_dict(self, score: float = 0.0) -> Dict[str, Any]:
        return {
            "doc_id": self.doc_id,
            "title": self.title,
            "standard": self.standard,
            "category": self.category,
            "tags": self.tags,
            "content": self.content,
            "remediation_snippet": self.remediation_snippet,
            "language": self.language,
            "relevance_score": round(score, 4),
        }


# Curated, authoritative post-quantum and classical cryptographic standards
STANDARDS_KNOWLEDGE: List[Dict[str, Any]] = [
    {
        "doc_id": "NIST-FIPS-203-ML-KEM",
        "title": "NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM)",
        "standard": "NIST FIPS 203 (August 2024)",
        "category": "PQC_KEM",
        "tags": ["ml-kem", "kyber", "kem", "key-exchange", "fips-203", "rsa", "ecdh", "x25519", "hybrid"],
        "content": (
            "NIST FIPS 203 specifies ML-KEM (derived from CRYSTALS-Kyber) as the primary standard for post-quantum "
            "key establishment. Parameter sets:\n"
            "- ML-KEM-512 (NIST Category 1, equivalent to AES-128)\n"
            "- ML-KEM-768 (NIST Category 3, equivalent to AES-192, default recommended for enterprise)\n"
            "- ML-KEM-1024 (NIST Category 5, equivalent to AES-256, required for high-assurance / CNSA 2.0)\n\n"
            "During the post-quantum migration era, hybrid key encapsulation mechanisms combining classical ECDH "
            "(X25519 or secp256r1) with ML-KEM (e.g. X25519MLKEM768) are strongly recommended to provide defense-in-depth "
            "against both classical implementation flaws and hypothetical quantum cryptanalytic breakthroughs.\n"
            "CRITICAL SPECIFICATION NOTE: ML-KEM is an encapsulation mechanism for symmetric shared secret generation. "
            "It CANNOT and MUST NOT be used for digital signatures."
        ),
        "remediation_snippet": (
            "# Python Hybrid Post-Quantum Key Exchange Concept (FIPS 203)\n"
            "# Combines classical X25519 with post-quantum ML-KEM-768\n"
            "from cryptography.hazmat.primitives.asymmetric import x25519\n"
            "# In hybrid mode: client sends both X25519 pubkey and ML-KEM-768 encapsulation"
        ),
    },
    {
        "doc_id": "NIST-FIPS-204-ML-DSA",
        "title": "NIST FIPS 204: Module-Lattice-Based Digital Signature Algorithm (ML-DSA)",
        "standard": "NIST FIPS 204 (August 2024)",
        "category": "PQC_SIGNATURE",
        "tags": ["ml-dsa", "dilithium", "signature", "fips-204", "rsa", "ecdsa", "ed25519", "pki"],
        "content": (
            "NIST FIPS 204 specifies ML-DSA (derived from CRYSTALS-Dilithium) as the primary standard for general-purpose "
            "post-quantum digital signatures. Parameter sets:\n"
            "- ML-DSA-44 (Category 2)\n"
            "- ML-DSA-65 (Category 3, primary recommended default for TLS, code signing, and identity)\n"
            "- ML-DSA-87 (Category 5, CNSA 2.0 target)\n\n"
            "ML-DSA replaces Shor-vulnerable classical public-key algorithms including RSA-2048/3072/4096 (PKCS#1 / PSS) "
            "and ECDSA (secp256r1, secp384r1, Ed25519). Public keys and signatures are significantly larger than classical equivalents, "
            "so message buffer sizes, MTU, and serialization schemas must be audited."
        ),
        "remediation_snippet": (
            "# Python Digital Signature Upgrade Requirement:\n"
            "# Replace classical RSA-1024/2048 and ECDSA with ML-DSA-65 for quantum resistance."
        ),
    },
    {
        "doc_id": "NIST-FIPS-205-SLH-DSA",
        "title": "NIST FIPS 205: Stateless Hash-Based Digital Signature Algorithm (SLH-DSA)",
        "standard": "NIST FIPS 205 (August 2024)",
        "category": "PQC_SIGNATURE",
        "tags": ["slh-dsa", "sphincs+", "hash-based", "fips-205", "firmware", "root-of-trust"],
        "content": (
            "NIST FIPS 205 standardizes SLH-DSA (derived from SPHINCS+), a stateless hash-based signature scheme. "
            "Security relies solely on the collision resistance and preimage resistance of underlying cryptographic hash functions "
            "(SHA-256, SHAKE-256) rather than structured lattice assumptions. Ideal as a conservative hedge for long-lived root keys, "
            "secure boot firmware, and digital certificates."
        ),
    },
    {
        "doc_id": "CNSA-2-0-NSA-MANDATES",
        "title": "NSA CNSA 2.0: Commercial National Security Algorithm Suite 2.0 Timelines",
        "standard": "NSA Cybersecurity Advisory (CNSA 2.0)",
        "category": "REGULATORY",
        "tags": ["cnsa", "cnsa-2.0", "nsa", "compliance", "timeline", "mandate", "fedramp"],
        "content": (
            "The NSA CNSA 2.0 transition timetable requires all National Security Systems and federal contractor boundaries to migrate:\n"
            "- Software & Firmware Signing: Begin transition immediately; complete exclusive PQC by 2025-2030.\n"
            "- Web Browsers, TLS, Network Equipment: Support hybrid PQC by 2026; exclusive PQC mandatory by 2033.\n"
            "- Operating Systems & Cloud Infrastructure: Mandatory PQC migration by 2033.\n"
            "- Algorithms: ML-KEM-1024, ML-DSA-87, SLH-DSA, AES-256, SHA-384, SHA-512."
        ),
    },
    {
        "doc_id": "GROVER-SYMMETRIC-AES256",
        "title": "Grover's Algorithm Impact on Symmetric Ciphers and Hash Functions",
        "standard": "Quantum Information Science & NIST SP 800-175B",
        "category": "SYMMETRIC",
        "tags": ["grover", "aes", "aes-128", "aes-256", "des", "3des", "rc4", "blowfish", "symmetric"],
        "content": (
            "Grover's quantum algorithm performs unstructured search with quadratic speedup (O(sqrt(N))), which effectively "
            "halves the bit security of symmetric ciphers and collision resistance of hash functions:\n"
            "- AES-128: Reduced to 64-bit effective quantum security (considered marginal/unsafe against CRQC).\n"
            "- AES-256: Reduced to 128-bit effective quantum security (fully secure against quantum adversaries).\n"
            "- DES (56-bit): Completely broken classically and in microseconds on quantum hardware.\n"
            "- 3DES (112-bit effective): Broken by Sweet32 64-bit block collision and quantum key exhaustion.\n"
            "- Remediation: Enforce AES-256 in Galois/Counter Mode (AES-256-GCM) with authenticated encryption (AEAD)."
        ),
        "remediation_snippet": (
            "# Python Safe Symmetric Cryptography (AES-256-GCM AEAD)\n"
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "import os\n\n"
            "key = AESGCM.generate_key(bit_length=256)  # 256-bit quantum-safe key\n"
            "aesgcm = AESGCM(key)\n"
            "nonce = os.urandom(12)  # 96-bit recommended GCM nonce\n"
            "ciphertext = aesgcm.encrypt(nonce, b'sensitive_payload', None)"
        ),
    },
    {
        "doc_id": "SHOR-ASYMMETRIC-RSA-ECC",
        "title": "Shor's Algorithm Impact on Asymmetric Primitives (RSA, DH, ECDSA, ECDH)",
        "standard": "Shor's Algorithm (Polynomial Time Discrete Log & Factorization)",
        "category": "PQC_KEM",
        "tags": ["shor", "rsa", "rsa-1024", "rsa-2048", "ecc", "ecdh", "ecdsa", "crqc", "hndl"],
        "content": (
            "Shor's quantum algorithm solves the integer factorization problem and the discrete logarithm problem in polynomial time (O((log N)^3)).\n"
            "- All classical public-key cryptography (RSA-1024, RSA-2048, RSA-4096, Diffie-Hellman, ECDSA, ECDH, Ed25519) "
            "is completely broken by a Cryptanalytically Relevant Quantum Computer (CRQC).\n"
            "- Harvest Now, Decrypt Later (HNDL): Adversaries are passively intercepting and storing encrypted traffic today. "
            "When CRQC emerges, stored ciphertext will be decrypted retroactively unless protected by post-quantum key encapsulation.\n"
            "- Remediation: Immediate deployment of hybrid ML-KEM-768 for TLS/data-in-transit, and minimum RSA-3072 / ML-DSA for classical fallback."
        ),
    },
    {
        "doc_id": "DEPRECATION-MD5-SHA1",
        "title": "Cryptographic Hash Deprecation: MD5 (RFC 6151) and SHA-1 (RFC 6194)",
        "standard": "IETF RFC 6151 / RFC 6194 / NIST SP 800-131A",
        "category": "HASH",
        "tags": ["md5", "sha-1", "sha1", "hash", "collision", "fips-180-4", "sha256", "sha3"],
        "content": (
            "MD5 and SHA-1 suffer from practical chosen-prefix collision attacks:\n"
            "- MD5: Collisions constructible in seconds on commodity laptops. Prohibited in all security contexts.\n"
            "- SHA-1: Broken by SHAttered (2017) and SHA-1 Chosen-Prefix Collision (2020). Deprecated by NIST with complete phaseout required.\n"
            "- Remediation: Replace with SHA-256 or SHA-512 (NIST FIPS 180-4) or SHA-3 / SHAKE (NIST FIPS 202). "
            "For password hashing, never use plain cryptographic hashes; use Argon2id, bcrypt, or PBKDF2-HMAC-SHA256."
        ),
        "remediation_snippet": (
            "# Python SHA-256 Replacement\n"
            "import hashlib\n"
            "secure_digest = hashlib.sha256(b'payload_data').hexdigest()"
        ),
    },
    {
        "doc_id": "RECIPE-PYTHON-PQC-REMEDIATION",
        "title": "Polyglot Remediation Recipe: Python Safe Cryptography",
        "standard": "ECDAT Secure Coding Standard (Python)",
        "category": "RECIPE",
        "language": "python",
        "tags": ["python", "hashlib", "cryptography", "aesgcm", "rsa", "sha256"],
        "content": (
            "Guidelines for remediating Python cryptographic vulnerabilities:\n"
            "1. Hashlib: Replace `hashlib.md5(...)` or `hashlib.sha1(...)` with `hashlib.sha256(...)`.\n"
            "2. Asymmetric RSA: If using `rsa.generate_private_key(key_size=1024)`, upgrade key_size to at least 3072.\n"
            "3. Symmetric Ciphers: Replace `Crypto.Cipher.DES` or `Blowfish` with `cryptography.hazmat.primitives.ciphers.aead.AESGCM`."
        ),
        "remediation_snippet": (
            "# Remediated Python Code Pattern\n"
            "import hashlib\n"
            "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\n"
            "from cryptography.hazmat.primitives.asymmetric import rsa\n\n"
            "def safe_crypto_pipeline(payload: bytes):\n"
            "    # Remediated: FIPS 180-4 SHA-256\n"
            "    checksum = hashlib.sha256(payload).hexdigest()\n"
            "    # Remediated: Quantum-safe symmetric AEAD\n"
            "    key = AESGCM.generate_key(bit_length=256)\n"
            "    aesgcm = AESGCM(key)\n"
            "    # Remediated: High-assurance RSA 3072 floor\n"
            "    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)\n"
            "    return checksum, priv_key"
        ),
    },
    {
        "doc_id": "RECIPE-NODEJS-PQC-REMEDIATION",
        "title": "Polyglot Remediation Recipe: Node.js / TypeScript Safe Cryptography",
        "standard": "ECDAT Secure Coding Standard (JavaScript/TypeScript)",
        "category": "RECIPE",
        "language": "javascript",
        "tags": ["javascript", "typescript", "node", "crypto", "aes-256-gcm", "sha256"],
        "content": (
            "Guidelines for remediating Node.js cryptographic vulnerabilities:\n"
            "1. Hashing: Replace `crypto.createHash('md5')` and `crypto.createHash('sha1')` with `crypto.createHash('sha256')`.\n"
            "2. Symmetric: Replace `crypto.createCipher('des', ...)` with `crypto.createCipheriv('aes-256-gcm', key, iv)`.\n"
            "3. Key Generation: In `crypto.generateKeyPairSync('rsa', { modulusLength: 1024 })`, increase modulusLength to 3072."
        ),
        "remediation_snippet": (
            "// Remediated Node.js Code Pattern\n"
            "import crypto from 'crypto';\n\n"
            "export function secureNodeCrypto(data: Buffer) {\n"
            "    const hash = crypto.createHash('sha256').update(data).digest('hex');\n"
            "    const key = crypto.randomBytes(32);\n"
            "    const iv = crypto.randomBytes(12);\n"
            "    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);\n"
            "    return { hash, key, iv };\n"
            "}"
        ),
    },
    {
        "doc_id": "RECIPE-GO-PQC-REMEDIATION",
        "title": "Polyglot Remediation Recipe: Golang Safe Cryptography",
        "standard": "ECDAT Secure Coding Standard (Go)",
        "category": "RECIPE",
        "language": "golang",
        "tags": ["go", "golang", "crypto/sha256", "crypto/aes", "crypto/cipher", "rsa"],
        "content": (
            "Guidelines for remediating Go cryptographic vulnerabilities:\n"
            "1. Hashing: Replace `md5.New()` or `sha1.New()` with `sha256.New()`.\n"
            "2. Symmetric: Replace `des.NewCipher(...)` with `aes.NewCipher(...)` wrapped in `cipher.NewGCM(block)`.\n"
            "3. RSA: In `rsa.GenerateKey(rand.Reader, 1024)`, update bit size to 3072."
        ),
        "remediation_snippet": (
            "// Remediated Go Code Pattern\n"
            "package main\n"
            "import (\n"
            "    \"crypto/aes\"\n"
            "    \"crypto/cipher\"\n"
            "    \"crypto/rand\"\n"
            "    \"crypto/sha256\"\n"
            "    \"io\"\n"
            ")\n"
            "func SecureGoCrypto(data []byte) ([]byte, error) {\n"
            "    h := sha256.Sum256(data)\n"
            "    key := make([]byte, 32)\n"
            "    io.ReadFull(rand.Reader, key)\n"
            "    block, _ := aes.NewCipher(key)\n"
            "    gcm, _ := cipher.NewGCM(block)\n"
            "    nonce := make([]byte, gcm.NonceSize())\n"
            "    io.ReadFull(rand.Reader, nonce)\n"
            "    return gcm.Seal(nonce, nonce, h[:], nil), nil\n"
            "}"
        ),
    },
    {
        "doc_id": "RECIPE-JAVA-PQC-REMEDIATION",
        "title": "Polyglot Remediation Recipe: Java Safe Cryptography",
        "standard": "ECDAT Secure Coding Standard (Java)",
        "category": "RECIPE",
        "language": "java",
        "tags": ["java", "messagedigest", "cipher", "aes/gcm/nopadding", "keypairgenerator", "bouncycastle"],
        "content": (
            "Guidelines for remediating Java cryptographic vulnerabilities:\n"
            "1. Hashing: Replace `MessageDigest.getInstance(\"MD5\")` or `\"SHA-1\"` with `\"SHA-256\"`.\n"
            "2. Cipher: Replace `Cipher.getInstance(\"DES\")` or `\"DESede\"` with `\"AES/GCM/NoPadding\"`.\n"
            "3. RSA: In `KeyPairGenerator.getInstance(\"RSA\")`, initialize with 3072 or 4096 bits."
        ),
        "remediation_snippet": (
            "// Remediated Java Code Pattern\n"
            "import java.security.MessageDigest;\n"
            "import javax.crypto.Cipher;\n"
            "import javax.crypto.spec.GCMParameterSpec;\n"
            "import javax.crypto.spec.SecretKeySpec;\n\n"
            "public class SecureJavaCrypto {\n"
            "    public static byte[] hashSHA256(byte[] input) throws Exception {\n"
            "        MessageDigest md = MessageDigest.getInstance(\"SHA-256\");\n"
            "        return md.digest(input);\n"
            "    }\n"
            "}"
        ),
    },
    {
        "doc_id": "RECIPE-C-CPP-PQC-REMEDIATION",
        "title": "Polyglot Remediation Recipe: C / C++ (OpenSSL 3.0+ & liboqs)",
        "standard": "ECDAT Secure Coding Standard (C/C++)",
        "category": "RECIPE",
        "language": "c_cpp",
        "tags": ["c", "cpp", "openssl", "sha256", "evp_aes_256_gcm", "liboqs", "mlkem"],
        "content": (
            "Guidelines for remediating C/C++ OpenSSL vulnerabilities:\n"
            "1. Hashing: Replace deprecated `MD5(...)` and `SHA1(...)` macros with `SHA256(...)` or EVP API.\n"
            "2. Symmetric: Replace `DES_ecb_encrypt` with `EVP_CIPHER_CTX` using `EVP_aes_256_gcm()`.\n"
            "3. Asymmetric: Use OpenSSL 3.2 FIPS provider or Open Quantum Safe (`liboqs`) for ML-KEM and ML-DSA."
        ),
        "remediation_snippet": (
            "// Remediated C Code Pattern (OpenSSL)\n"
            "#include <openssl/sha.h>\n"
            "#include <openssl/evp.h>\n\n"
            "void secure_c_hash(const unsigned char *data, size_t len, unsigned char *out_md) {\n"
            "    SHA256(data, len, out_md);\n"
            "}"
        ),
    },
]


def tokenize(text: str) -> List[str]:
    """Extracts lowercase alphabetic/numeric tokens, preserving technical hyphenated terms."""
    clean = text.lower()
    tokens = re.findall(r'[a-z0-9]+(?:[-_][a-z0-9]+)*', clean)
    return tokens


class PqcRAGEngine:
    """In-memory TF-IDF / BM25 Knowledge Retriever for Post-Quantum Cryptography."""

    def __init__(self, knowledge_dir: Optional[str] = None):
        self.documents: List[RAGDocument] = []
        self.doc_tokens: List[Set[str]] = []
        self.df: Dict[str, int] = {}  # Document frequency of terms
        self.avg_doc_len: float = 0.0
        self._load_knowledge(knowledge_dir)

    def _load_knowledge(self, knowledge_dir: Optional[str] = None):
        """Loads static standards and dynamic knowledge files from backend/knowledge."""
        # 1. Load embedded standards
        for item in STANDARDS_KNOWLEDGE:
            doc = RAGDocument(
                doc_id=item["doc_id"],
                title=item["title"],
                standard=item["standard"],
                category=item["category"],
                tags=item.get("tags", []),
                content=item["content"],
                remediation_snippet=item.get("remediation_snippet"),
                language=item.get("language"),
            )
            self.documents.append(doc)

        # 2. Load JSON files from backend/knowledge if available
        base_dir = knowledge_dir or os.path.join(os.path.dirname(__file__), "..", "knowledge")
        if os.path.isdir(base_dir):
            try:
                pqc_path = os.path.join(base_dir, "pqc_migration_knowledge.json")
                if os.path.exists(pqc_path):
                    with open(pqc_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        targets = data.get("migration_targets", {})
                        for role, target_info in targets.items():
                            doc = RAGDocument(
                                doc_id=f"KNOWLEDGE-MIGRATION-{role}",
                                title=f"Migration Target for {role}",
                                standard=f"NIST Post-Quantum Standard ({target_info.get('pqc_target', 'PQC')})",
                                category="PQC_TARGET",
                                tags=[role.lower(), "migration", "pqc", "nist"],
                                content=f"Target: {target_info.get('pqc_target')}\nHybrid: {target_info.get('hybrid_target', 'N/A')}\nRationale: {target_info.get('rationale', '')}",
                            )
                            self.documents.append(doc)
            except Exception:
                pass

        # 3. Compute Term Frequencies and Index
        total_len = 0
        for doc in self.documents:
            combined = f"{doc.title} {doc.standard} {doc.category} {' '.join(doc.tags)} {doc.content} {doc.language or ''}"
            tokens = set(tokenize(combined))
            self.doc_tokens.append(tokens)
            total_len += len(tokens)
            for t in tokens:
                self.df[t] = self.df.get(t, 0) + 1

        self.avg_doc_len = total_len / max(1, len(self.documents))

    def retrieve(
        self,
        query: str,
        language: Optional[str] = None,
        category: Optional[str] = None,
        top_k: int = 3,
    ) -> List[Dict[str, Any]]:
        """Retrieves top-k relevant post-quantum cryptographic standards and guidance."""
        query_tokens = tokenize(query)
        if not query_tokens:
            # Return default fundamental standards
            return [d.to_dict(1.0) for d in self.documents[:top_k]]

        num_docs = len(self.documents)
        scored: List[Tuple[float, RAGDocument]] = []

        lang_norm = (language or "").lower()

        for idx, doc in enumerate(self.documents):
            doc_tokens = self.doc_tokens[idx]
            score = 0.0

            # Language affinity boost
            if doc.language and lang_norm:
                if doc.language == lang_norm:
                    score += 1.5
                else:
                    # Penalize other-language specific recipes
                    score -= 1.0

            # Category filter if provided
            if category and doc.category != category:
                score -= 0.5

            for q in query_tokens:
                if q in doc_tokens:
                    # Inverse document frequency
                    doc_freq = self.df.get(q, 1)
                    idf = math.log((num_docs - doc_freq + 0.5) / (doc_freq + 0.5) + 1.0)

                    # Tag match bonus
                    tag_bonus = 2.0 if q in doc.tags else 1.0
                    title_bonus = 1.8 if q in doc.title.lower() else 1.0

                    score += idf * tag_bonus * title_bonus

            # Bonus for exact primitive acronym matches
            upper_query = query.upper()
            if "ML-KEM" in upper_query and "ML-KEM" in doc.title:
                score += 3.0
            if "ML-DSA" in upper_query and "ML-DSA" in doc.title:
                score += 3.0
            if ("RSA" in upper_query or "1024" in upper_query) and "RSA" in doc.title:
                score += 2.5
            if "MD5" in upper_query and "MD5" in doc.title:
                score += 2.5
            if "DES" in upper_query and "DES" in doc.title:
                score += 2.5
            if "CNSA" in upper_query and "CNSA" in doc.title:
                score += 2.5

            if score > 0:
                scored.append((score, doc))

        scored.sort(key=lambda x: x[0], reverse=True)
        results = [doc.to_dict(score) for score, doc in scored[:top_k]]

        # If no positive matches, fallback to general PQC KEM & Signature guidance
        if not results:
            results = [d.to_dict(0.5) for d in self.documents[:top_k]]

        return results

    def format_context_for_llm(self, retrieved: List[Dict[str, Any]]) -> str:
        """Formats retrieved standards as structured contextual injection for DeepSeek-R1."""
        blocks = []
        for idx, r in enumerate(retrieved, 1):
            block = (
                f"--- [RAG Standard {idx}: {r['title']}] ---\n"
                f"Standard Reference: {r['standard']} (Category: {r['category']})\n"
                f"Authoritative Specification:\n{r['content']}\n"
            )
            if r.get("remediation_snippet"):
                block += f"Reference Implementation Pattern:\n{r['remediation_snippet']}\n"
            blocks.append(block)

        return "\n".join(blocks)


# Singleton instance for fast in-memory query execution
rag_engine = PqcRAGEngine()
