# ECDAT V4 — P4.2 Benchmark Methodology & Research Protocol

## 1. Research Protocol & Objective

The primary research objective of Phase P4 is transforming ECDAT from an engineering platform into an **empirically evaluable cryptographic intelligence system**.

The benchmark answers five central empirical questions:
1. **Classification Consistency**: Can ECDAT consistently classify cryptographic observations across polyglot languages and deployment environments?
2. **Taxonomic Discrimination**: How accurately does it distinguish between:
   $$\text{IMPORT} \ne \text{STRING} \ne \text{SYMBOL} \ne \text{DEPENDENCY} \ne \text{CAPABILITY} \ne \text{ADVERTISEMENT} \ne \text{NEGOTIATION} \ne \text{ACTUAL\_USE}$$
3. **Multi-Modal Corroboration**: How does multi-source evidence affect detection confidence and contradiction resolution?
4. **Failure Topography**: What are the precise false-positive and false-negative patterns across modalities?
5. **Deterministic Reproducibility**: Can the system reproduce exact numeric metrics and content digests across runs, hosts, and knowledge base versions?

---

## 2. Dataset Composition (736 Controlled Fixtures)

All cases in `backend/evaluation/datasets/ground_truth_v1.yaml` are explicitly labeled `dataset_type: "SYNTHETIC"`.

### Modality Distribution:
- **SOURCE**: 130 cases (Python, Java, C/C++, Go, Rust, JavaScript)
- **DEPENDENCY**: 130 cases (requirements.txt, package.json, pom.xml, go.mod, Cargo.toml)
- **BINARY**: 135 cases (ELF, Mach-O, PE with embedded byte signatures, S-boxes, OIDs)
- **FIRMWARE**: 50 cases (uImage, ZIP, embedded certificates)
- **NETWORK**: 142 cases (TLS 1.0–1.3, SSH KEX banners, QUIC Alt-Svc probes)
- **X509**: 75 cases (RSA, ECDSA, Ed25519 cert chains, AIA OCSP extensions)
- **PQC**: 74 cases (ML-KEM, ML-DSA, SLH-DSA, hybrid KEX)

---

## 3. The 20 Mandatory Hard Negative Categories

| Category | Description | Ground Truth Label | Expected Use State |
|:---|:---|:---:|:---:|
| `HN1` | Crypto library imported but zero APIs called | `NEGATIVE` | `IMPORT_ONLY` |
| `HN2` | Cryptographic algorithm string in logs or comments | `NEGATIVE` | `STRING_ONLY` |
| `HN3` | Binary rodata contains symbol string without instructions | `NEGATIVE` | `STRING_ONLY` |
| `HN4` | Dependency package declared in manifest but unused in code | `NEGATIVE` | `DEPENDENCY_DECLARED` |
| `HN5` | Cryptographic API invocation is commented out in source | `NEGATIVE` | `UNUSED` |
| `HN6` | Cryptographic API call inside dead-code branch (`if False:`) | `NEGATIVE` | `UNUSED` |
| `HN7` | Algorithm name appears solely in module documentation | `NEGATIVE` | `STRING_ONLY` |
| `HN8` | Algorithm name appears only in variable identifier | `NEGATIVE` | `STRING_ONLY` |
| `HN9` | Cipher suite advertised in ClientHello but server selected another | `NEGATIVE` | `ADVERTISED_ONLY` |
| `HN10` | Server supports legacy TLS version but connection negotiated TLS 1.3 | `NEGATIVE` | `ADVERTISED_ONLY` |
| `HN11` | SSH legacy KEX algorithm advertised in banner but not chosen | `NEGATIVE` | `ADVERTISED_ONLY` |
| `HN12` | HTTP/3 Alt-Svc header present without active UDP handshake | `NEGATIVE` | `ADVERTISED_ONLY` |
| `HN13` | Expired or untrusted self-signed certificate in chain | `NEGATIVE` | `UNUSED` |
| `HN14` | OCSP AIA extension present in cert but revocation check not run | `NEGATIVE` | `CAPABILITY_ONLY` |
| `HN15` | Hybrid KEX (X25519MLKEM768) falsely claimed as PQC signature | `NEGATIVE` | `CAPABILITY_ONLY` |
| `HN16` | Provider package present in build manifest without runtime registration | `NEGATIVE` | `CAPABILITY_ONLY` |
| `HN17` | Firmware header has signature string without executable code | `NEGATIVE` | `STRING_ONLY` |
| `HN18` | Cipher configuration in env file without server reload support | `NEGATIVE` | `CONFIGURATION_ONLY` |
| `HN19` | Network scanner probe blocked by EDR driver | `INCONCLUSIVE` | `SCANNER_UNAVAILABLE` |
| `HN20` | High-entropy packed binary with stripped symbols | `UNKNOWN` | `UNKNOWN` |

---

## 4. Anti-Fake Evaluator Protocol

To prevent evaluation bias and verify research validity:
1. The evaluator **never inspects** `ground_truth_label` or `expected_*` fields during inference.
2. The evaluator feeds raw artifacts into the actual scanners (`scan_sources`, `DependencyScanner`, `BinarySignatureMatcher`, `BinaryStringExtractor`, `AlgorithmRegistry`).
3. An automated test (`test_axiom_35_anti_fake_evaluator_mutation_alters_prediction`) mutates the input code artifact while keeping `ground_truth_label="POSITIVE"`, proving that the prediction changes to `NEGATIVE` solely based on scanner execution.
