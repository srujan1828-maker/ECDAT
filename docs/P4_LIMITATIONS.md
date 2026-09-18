# ECDAT V4 — P4 Research Limitations & Scope Boundaries

## 1. Synthetic Fixture Caveats

- **Controlled Synthetic Bias**: All 736 benchmark cases were deterministically synthesized for verification of taxonomic boundaries. While designed with realistic code snippets, manifests, byte payloads, and network headers, synthetic tests do not reproduce the chaotic variety of real-world enterprise codebases.
- **No Claim of Production Generalizability**: ECDAT makes **no claim of 100% production accuracy** based on these benchmark results. Production codebases with obfuscation, dynamic reflection, proprietary crypto wrappers, or unconventional build tooling will exhibit different error distributions.

---

## 2. Modality & Language Limitations

- **Polyglot Heuristic Gap**: Python AST scanning achieves high precision and recall due to syntax tree analysis. Languages relying on regex heuristics (Go, Rust, C++) lack full interprocedural dataflow analysis, resulting in higher false negative rates when novel wrapper abstractions are used.
- **Binary Static Analysis Limits**: Binary signature and constant matching is bounded by uncompressed, unstripped, or standard compilation targets. Heavily packed, encrypted, or metamorphic binaries are correctly flagged as `UNKNOWN` rather than decoded.
- **Network Probe Scope**: Network analyzers evaluate advertised and negotiated parameters on open ports. They cannot inspect encrypted payload contents without TLS termination or MITM proxies.

---

## 3. Evidence Distinction Guardrails

ECDAT maintains strict taxonomic boundaries:
- `MEASURED != INFERRED != ESTIMATED != UNMEASURED`
- `SCANNER_UNAVAILABLE` is strictly isolated from negative evidence (`NOT_OBSERVED`).
- The absence of evidence is never converted into positive assurance of safety or low risk.
