# ECDAT V4 — Binary Cryptographic Analysis Architecture

## 1. Executive Summary & Research Foundations

The **ECDAT V4 Binary Analysis Subsystem** is an evidence-driven, pure-Python discovery engine capable of inspecting compiled executables across major operating system formats:
- **Linux/UNIX ELF** (ELF32, ELF64, Little-Endian, Big-Endian, x86, x86_64, ARM, AArch64, MIPS, RISC-V)
- **Windows PE/COFF** (PE32, PE32+, x86, x64, ARM64)
- **macOS Mach-O** (32-bit, 64-bit, and Universal Fat binaries)

The core architecture operates under non-negotiable research axioms:
$$\text{STRING} \neq \text{USE}, \quad \text{IMPORT} \neq \text{USE}, \quad \text{SYMBOL} \neq \text{USE}, \quad \text{LIBRARY} \neq \text{USE}, \quad \text{DISASSEMBLY} \neq \text{EXECUTION}$$

Every observation emitted by the binary discovery pipeline carries an explicit **Evidence Level ($E1..E3$)**, a formal **EvidenceState (`MEASURED`)**, cryptographic provenance (input SHA-256 and byte offset), and documented epistemic limitations.

---

## 2. Structural Inspection & Metadata Recovery

The binary parser recovers structural metadata directly from binary bytes using standard Python standard library constructs (`struct`, `io`) with zero unpinned binary tooling dependencies:

### 2.1 ELF Headers & Section Tables
- **Architecture & Machine**: Identifies machine codes (`EM_386`, `EM_X86_64`, `EM_ARM`, `EM_AARCH64`, `EM_MIPS`, `EM_RISCV`).
- **Section Headers**: Enumerates all sections (`.text`, `.rodata`, `.data`, `.symtab`, `.strtab`, `.dynamic`, `.dynstr`), resolving virtual addresses, file offsets, sizes, and permissions (executable, readable, writable).
- **Stripped Status**: Distinguishes unstripped binaries containing `.symtab` from production-stripped binaries.
- **GNU Build ID**: Extracts cryptographic build identifiers from `.note.gnu.build-id` SHT_NOTE sections.

### 2.2 PE/COFF Inspection
- **Headers**: Traverses DOS MZ header (`e_lfanew`) to PE signature, COFF file header, and PE optional headers.
- **Section Headers**: Recovers `.text`, `.rdata`, `.data`, `.pdata`, and calculates per-section Shannon entropy.
- **Timestamps & Subsystem**: Captures PE compilation timestamps (`TimeDateStamp`) and image characteristics.

### 2.3 Mach-O Load Commands
- **Segments & Sections**: Traverses `LC_SEGMENT` and `LC_SEGMENT_64` load commands (`__TEXT`, `__DATA`, `__RODATA`).
- **Universal Binaries**: Detects FAT header magic (`0xcafebabe`) and multi-architecture payloads.

---

## 3. Symbol Discovery & Epistemic Classification

The symbol analyzer extracts both static and dynamic symbols and categorizes them with rigorous semantic boundaries:

| Symbol Class | Meaning | Evidence Level | Epistemic Limitation |
| :--- | :--- | :--- | :--- |
| **Defined Function (`is_defined: True`)** | Function code is compiled directly into the binary's text segment. | **E3** | Shows compiled presence; runtime execution depends on dynamic control flow. |
| **Undefined Imported Symbol (`is_defined: False`)** | Function is imported from an external shared library (e.g. `SHN_UNDEF` in ELF). | **E2** | Shows external API dependency; invocation occurs only if caller reachable. |
| **Exported Function (PE)** | Function is exported by the binary for external consumers. | **E3** | Function implementation present in export table. |
| **Imported IAT Function (PE)** | Function is referenced in Import Address Table. | **E2** | Dynamic linkage dependency. |

### Cryptographic Symbol Knowledge Mapping
Symbols are automatically mapped to standard cryptographic families, primitives, and PQC transition classifications:
- **PQC / Post-Quantum**: `crypto_kem_*`, `*kyber*`, `*dilithium*`, `*sphincs*`, `*falcon*` $\rightarrow$ `PQC_STANDARDIZED`
- **Classical Asymmetric**: `RSA_*`, `ECDSA_*`, `EC_KEY_*`, `X25519_*` $\rightarrow$ `QUANTUM_VULNERABLE`
- **Symmetric Ciphers**: `AES_*`, `ChaCha20_*`, `DES_*`, `SM4_*` $\rightarrow$ `QUANTUM_RESISTANT_PQC_TRANSITION_RECOMMENDED` or `LEGACY_BROKEN`
- **Hashes**: `SHA256_*`, `SHA3_*`, `MD5_*`, `SHA1_*` $\rightarrow$ `QUANTUM_RESISTANT` or `LEGACY_BROKEN`

---

## 4. Shared Library & Import Dependency Analysis

The engine resolves dynamically linked shared objects:
- **ELF `DT_NEEDED`**: Extracted from `SHT_DYNAMIC` records, resolving library names via `.dynstr`.
- **PE Import Directory**: Parses `IMAGE_IMPORT_DESCRIPTOR` structures to extract required DLLs (`bcrypt.dll`, `crypt32.dll`, `ncrypt.dll`, `libcrypto-3.dll`).
- **Mach-O `LC_LOAD_DYLIB`**: Extracts dynamic dylib dependencies.

Libraries are matched against known cryptographic providers (OpenSSL, Windows CNG, Windows CryptoAPI, libsodium, wolfSSL, mbedTLS, liboqs). Linking against `bcrypt.dll` generates an $E2$ evidence item for the cryptographic library, but does not assert which specific algorithms are used at runtime.

---

## 5. Byte Signatures, Tables & Constants Knowledge Base

The binary engine scans raw binary sections against `backend/knowledge/binary_crypto_signatures.yaml`:
1. **Symmetric Constants**:
   - AES forward Rijndael S-box (32-byte prefix `0x63, 0x7c, 0x77...`)
   - AES inverse S-box (`0x52, 0x09, 0x6a...`)
   - DES initial permutation table
   - ChaCha20 constants (`"expand 32-byte k"`)
   - SM4 block cipher S-box
   - Blowfish P-array
2. **Hash Initial Chaining State Vectors**:
   - MD5 IV (little-endian: `0x01, 0x23, 0x45, 0x67...`)
   - SHA-1 IV (big-endian: `0x67, 0x45, 0x23, 0x01...`)
   - SHA-256 IV (`0x6a, 0x09, 0xe6, 0x67...`)
   - SHA-384 / SHA-512 IVs
   - Keccak-f[1600] permutation round constants
   - Automatic 32-bit **word reversal** testing to detect cross-endian architectures without false negatives.
3. **PQC Polynomial & NTT Constants**:
   - FIPS 203 ML-KEM / Kyber NTT roots of unity ($\zeta$ twiddle factors)
   - FIPS 204 ML-DSA / Dilithium NTT constants
   - SLH-DSA / SPHINCS+ domain separators
4. **ASN.1 DER Object Identifiers (OIDs)**:
   - RSA encryption (`1.2.840.113549.1.1.1`)
   - Ed25519 (`1.3.101.112`)
   - secp256r1 (`1.2.840.10045.3.1.7`)
   - ML-KEM-768 (`2.16.840.1.101.3.4.4.2`)
   - ML-DSA-65 (`2.16.840.1.101.3.4.3.18`)

Offsets of signature matches are correlated with containing sections (e.g., matching in `.rodata` upgrades confidence and assigns Evidence Level $E2$).

---

## 6. Secret Masking & Key Confidentiality

Embedded credentials and private keys are detected via regex pattern matchers:
- PEM RSA Private Keys (`-----BEGIN RSA PRIVATE KEY-----`)
- PEM EC Private Keys (`-----BEGIN EC PRIVATE KEY-----`)
- OpenSSH Private Keys (`-----BEGIN OPENSSH PRIVATE KEY-----`)
- Encrypted Private Keys (`-----BEGIN ENCRYPTED PRIVATE KEY-----`)
- X.509 Certificates (`-----BEGIN CERTIFICATE-----`)

### STRICT SECURITY MANDATE:
Raw private key material is **NEVER** returned in API responses, logs, or evidence objects.
The payload is strictly masked with `SECRET_INDICATOR_DETECTED`.
Cryptographic parsers validate that the PEM structure is syntactically sound, determine key size where possible, and emit an $E3$ evidence record with severity `CRITICAL` without leaking secrets.

---

## 7. Deep Reverse Engineering Engine Plugins

ECDAT V4 defines a pluggable `DiscoveryEngine` interface for optional heavy reverse engineering tools:
- `GhidraEngine`: Headless decompiler and decompilation analysis
- `AngrEngine`: Symbolic execution and CFG reachability
- `YaraEngine`: Pattern matching rule engine

### Health & Observability:
When external tools or Python packages are not installed:
1. The engine's `health()` reports `status: "SCANNER_UNAVAILABLE"` with an explicit explanation.
2. The pipeline does **NOT** crash.
3. The platform does **NOT** falsely assert that the binary contains no cryptography.
