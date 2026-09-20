# ECDAT V4 — Advanced Source-Code Cryptographic Intelligence

## 1. Executive Summary & Research Foundations

In cryptographic discovery, naive pattern-matching engines conflate source-code appearances with cryptographic operation. Scanning for strings like `"RSA"` or searching for `import cryptography` generates unacceptably high false-positive rates when:
1. Libraries are imported for unused legacy utilities (`IMPORT`).
2. Mentions appear in code comments or design documentation (`COMMENT`).
3. Algorithm names appear as string literals for protocol labels, serialization identifiers, or dictionary keys (`STRING_LITERAL`).

ECDAT V4 enforces the fundamental research axiom:
$$\text{IMPORT} \neq \text{ACTUAL\_USE}, \quad \text{STRING\_LITERAL} \neq \text{ACTUAL\_USE}, \quad \text{COMMENT} \neq \text{ACTUAL\_USE}$$

Only confirmed invocations of verified cryptographic operations—instantiating ciphers, generating key pairs, hashing buffers, initializing MACs, or invoking low-level primitives—are classified as **`ACTUAL_USE`** ($E1$ Evidence).

---

## 2. Dual-Engine Architecture: Fast AST vs. Deep Tree-sitter

ECDAT V4 implements a tiered, resilient parsing architecture:

```mermaid
flowchart TD
    A[Source File] --> B{Deep Scan Enabled & Grammar Available?}
    B -- Yes --> C[Tree-Sitter Concrete Syntax Tree Parser]
    B -- No / Fallback --> D[Python AST / Robust Pattern Fallback]
    C --> E[CST Node Traversal & Context Resolution]
    D --> F[Surface Candidate Extraction]
    E --> G[Crypto Sink Matcher: crypto_sinks.yaml]
    G --> H{Matches Cryptographic Sink?}
    H -- Yes (API Call) --> I[Classify ACTUAL_USE (E1 Evidence)]
    H -- Import Only --> J[Classify IMPORT (E0 Evidence)]
    H -- Comment --> K[Classify COMMENT (Suppressed / Non-Asset)]
    H -- Unverified String --> L[Classify STRING_LITERAL (Candidate E0)]
    I --> M[Constant Propagation Engine]
    M --> N[Call Graph Extractor: CALLS Edges]
    N --> O[Asset Graph Ingestion]
```

### 2.1 Deep Tree-Sitter Concrete Syntax Tree (CST) Parser
- Engine: `backend/engine/treesitter_scanner.py`
- Grammars: Python, Java, C, C++, Go, Rust, JavaScript, TypeScript.
- Traversal: Recursively traverses named CST nodes, distinguishing `call_expression`, `method_invocation`, `import_statement`, `string_literal`, and `comment`.
- Extractors:
  - Language-specific call target resolution (e.g., combining Java `object.name` $\to$ `Cipher.getInstance`).
  - Argument extraction with AST literal resolution (e.g., string arguments for transformation strings `"AES/GCM/NoPadding"`).
  - Enclosing function extraction (`function_definition`, `method_declaration`, `FunctionDeclaration`) to identify caller context.

### 2.2 Fast Python AST & Syntax Fallback
- Standard Python `ast.parse` for fast-path scans.
- Graceful degradation: If a file contains syntax errors or unsupported grammar constructs, parsing does not abort the scan. A resilient fallback extracts surface candidates, marks `status: error` in coverage manifests, and prevents silent false negatives.

---

## 3. Cryptographic Sink Database (`crypto_sinks.yaml`)

Cryptographic operations are resolved against a centralized, versioned cryptographic sink knowledge base (`backend/knowledge/crypto_sinks.yaml`). Sinks represent programmatic APIs across standard runtimes:

| Language | Target Library / Module | Cryptographic Sinks Detected | Capability |
| :--- | :--- | :--- | :--- |
| **Python** | `cryptography.hazmat`, `hashlib`, `Crypto.Cipher` | `generate_private_key`, `Cipher`, `hashlib.sha256`, `hmac.new` | Asymmetric, Symmetric, Hash, MAC |
| **Java** | `javax.crypto`, `java.security` | `Cipher.getInstance`, `KeyPairGenerator.getInstance`, `MessageDigest.getInstance`, `Signature.getInstance` | Symmetric, Asymmetric, Hash, Signature |
| **C / C++** | `openssl/evp.h`, `openssl/rsa.h` | `EVP_CIPHER_CTX_new`, `EVP_aes_*`, `EVP_DigestInit`, `RSA_generate_key_ex`, `HMAC_Init_ex` | Low-level CPG / FFI cryptographic APIs |
| **Go** | `crypto/aes`, `crypto/rsa`, `crypto/sha256` | `aes.NewCipher`, `rsa.GenerateKey`, `sha256.New`, `ecdsa.GenerateKey` | Standard Go Cryptographic Packages |
| **Rust** | `aes_gcm`, `rsa`, `sha2`, `ed25519_dalek` | `Aes256Gcm::new`, `RsaPrivateKey::new`, `Sha256::new`, `SigningKey::generate` | Modern memory-safe crates |
| **JS / TS** | `node:crypto`, `crypto` | `createCipheriv`, `createHash`, `generateKeyPairSync`, `createHmac` | Server-side & Node.js WebCrypto |

---

## 4. Constant Propagation & Parameter Resolution

Cryptographic APIs often receive algorithms and key lengths via constants or variable bindings rather than inline literals:

```python
# config.py
DEFAULT_KEY_SIZE = 2048

# auth.py
from config import DEFAULT_KEY_SIZE
KEY_SIZE = DEFAULT_KEY_SIZE

# crypto_service.py
from auth import KEY_SIZE
key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
```

ECDAT V4 incorporates:
1. **Intra-File Constant Resolution**:
   - Traverses assignment statements (`assign` / `assignment_expression`).
   - Tracks constant literal bindings (`str`, `int`, numeric types).
   - Replaces variable identifiers at call sites with resolved values.
2. **Multi-Hop Cross-File Constant Propagation**:
   - Ingests top-level variable definitions and exports across scanned source files.
   - Maps import declarations to exported symbols.
   - Resolves dependencies across up to 3 cross-file hops.
   - Falls back to `"UNKNOWN"` if constants originate from dynamic network calls, unparsed configuration files, or database queries.

---

## 5. Call Graph & Blast Radius Integration

Every confirmed `ACTUAL_USE` observation records its enclosing caller context:
- Caller Function / Class / Module (e.g. `auth_service.generate_token`).
- Target Cryptographic Asset (e.g. `RSA-2048`).

During scan ingestion (`backend/engine/scan_store.py`):
1. A service asset (`AssetType.SERVICE`) is instantiated for the caller function.
2. An algorithm asset (`AssetType.ALGORITHM`) is instantiated for the cryptographic primitive.
3. A directed `CALLS` edge (`RelationshipType.CALLS`) is inserted into `graph_edges`:
   $$\text{auth\_service.generate\_token} \xrightarrow{\text{CALLS}} \text{RSA-2048}$$
4. When evaluating quantum exposure or vulnerability deprecation, the **Blast Radius Engine** walks backward along inbound `CALLS` edges to pinpoint all upstream functions, microservices, and applications affected by the deprecation of that cryptographic asset.

---

## 6. Soundness, Completeness & Limitations

ECDAT V4 is designed as a research-grade static intelligence engine:
- **Soundness (Minimizing False Positives)**:
  - Strong classification guarantees: imports, comments, and strings never become cryptographic assets.
  - Sinks require matching function names and appropriate argument counts.
- **Completeness & Known Boundaries**:
  - **Dynamic Evaluation**: `eval()`, Python `getattr()`, and dynamic string construction cannot be statically resolved without symbolic execution.
  - **Reflection**: Java `Class.forName()` or C++ `dlsym()` require runtime tracing (P1.3 / eBPF).
  - **Dead Code**: Static analysis detects actual calls present in the codebase, regardless of whether that control flow branch is actively executed at runtime. Runtime validation is augmented in P1.3.
