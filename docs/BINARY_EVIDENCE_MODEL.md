# ECDAT V4 — Binary Evidence Model & Epistemic Governance

## 1. Non-Negotiable Research Axioms

In binary and firmware cryptographic discovery, observation must never be conflated with execution:
$$\text{STRING} \neq \text{USE}, \quad \text{IMPORT} \neq \text{USE}, \quad \text{SYMBOL} \neq \text{USE}, \quad \text{LIBRARY} \neq \text{USE}, \quad \text{DISASSEMBLY} \neq \text{EXECUTION}$$

To maintain research-grade integrity, ECDAT V4 enforces a rigorous taxonomic separation between:
1. **What was measured** (exact byte sequence, symbol name, header offset).
2. **What was inferred** (algorithm classification, key length).
3. **What was estimated** (statistical entropy, confidence score).
4. **What cannot be verified** (dynamic runtime execution path without dynamic tracing).

---

## 2. Evidence Levels ($E0..E5$) in Binary Discovery

| Level | Formal Semantics | Binary Discovery Context | Example Observation |
| :--- | :--- | :--- | :--- |
| **E0** | Unmeasured | No binary analysis performed; engine disabled or unavailable. | Scanner unavailable metadata. |
| **E1** | Pattern Candidate | String literal or unmapped constant matching a crypto name. | ASCII `"AES-256-GCM"` or `"secp256r1"` string in read-only data. |
| **E2** | Structured Asset | Section-correlated byte signature, imported API symbol, or shared library link. | AES S-box located in `.rodata`; `AES_encrypt` listed in dynamic import table; `DT_NEEDED: libcrypto.so.3`. |
| **E3** | Actual Reference | Compiled function definition in binary text segment, parsed private key, or parsed certificate. | Defined symbol `AES_encrypt` in `.symtab`; parsed unencrypted RSA private key. |
| **E4** | Path Reachability | Control flow graph traces reachability from entrypoint to crypto call. | angr/Ghidra recovered call path from `main` to `EVP_EncryptInit`. |
| **E5** | Live Protocol Behavior | Observed live wire protocol exchange. | Network handshake negotiating TLS cipher suite. |

---

## 3. Observation Types & Mandatory Epistemic Limitations

Every evidence object emitted by `BinaryEvidenceGenerator` contains explicit `limitations` preventing overstatement of findings:

### 3.1 `ObservationType.BINARY_SIGNATURE`
- **Measurement**: Constant byte sequence (e.g. S-Box, IV, NTT table, or ASN.1 OID) identified at exact byte offset.
- **Level**: $E2$ if located within a recognized section (`.rodata`, `.rdata`, `.data`), $E1$ if in raw unsegmented bytes.
- **Mandatory Limitation**:
  `"Static observation of byte constant or S-box table. Presence in binary does not prove runtime invocation or specific key size."`

### 3.2 `ObservationType.BINARY_SYMBOL`
- **Measurement**: Symbol name extracted from `.symtab` or `.dynsym`.
- **Level**:
  - **$E3$** if `is_defined: True` (compiled function in binary).
  - **$E2$** if `is_defined: False` (imported dynamic external API).
- **Mandatory Limitation**:
  `"Symbol observed in binary symbol table as [defined/imported]. Dynamic reachability or runtime invocation path is not proven without dynamic tracing."`

### 3.3 `ObservationType.BINARY_REFERENCE`
- **Measurement**: Shared library dependency declaration (`DT_NEEDED`, PE Import Directory DLL, Mach-O dylib).
- **Level**: $E2$.
- **Mandatory Limitation**:
  `"Binary links against shared cryptographic library. Specific algorithms used at runtime cannot be confirmed from dependency declaration alone."`

### 3.4 `ObservationType.HARDCODED_KEY`
- **Measurement**: PEM private key header detected and verified via cryptographic parser.
- **Level**: $E3$.
- **Confidentiality Rule**: Raw private key material is masked as `SECRET_INDICATOR_DETECTED`.
- **Mandatory Limitation**:
  `"Static detection of embedded credential material. Raw private key material is masked as SECRET_INDICATOR_DETECTED."`

### 3.5 `ObservationType.X509_CERTIFICATE`
- **Measurement**: Parsed public X.509 certificate structure.
- **Level**: $E3$.
- **Mandatory Limitation**:
  `"Parsed embedded certificate; its presence alone is not a vulnerability."`

---

## 4. Immutable Provenance Schema

Each evidence record links back to an immutable `Provenance` block:
```json
{
  "input_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "source_engine": "binary_discovery",
  "engine_version": "4.0.0",
  "scan_id": "scan-e6b72d24-8f4b-4b11-9a7c-8646b9a89c99",
  "location": "crypto_daemon.elf:0x00001000",
  "timestamp": "2026-09-17T23:00:00.000000Z"
}
```

This provenance allows any audit, compliance engine, or verification pass to pinpoint the exact binary byte offset, input hash, and pipeline version that generated the discovery.
