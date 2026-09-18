# ECDAT V4 — P4.1 Knowledge Base Architecture

## 1. Executive Summary & Design Principles

The ECDAT V4 Cryptographic Knowledge Base Architecture establishes a **federated, versioned knowledge layer** over independently maintained rule definitions across the platform.

### Core Architecture Axioms:
1. **Clean-Room Federation**: Rather than copying, duplicating, or mutating frozen YAML knowledge sources, `backend/knowledge/crypto_knowledge.yaml` acts as a federated manifest referencing all authoritative knowledge sources.
2. **Deterministic Checksum Integrity**: Every referenced knowledge source has a recorded SHA-256 digest verified at boot/load time. Modifying any underlying YAML file invalidates the checksum and alters the deterministic `knowledge_hash`.
3. **Environment & Time Invariance**: Deterministic knowledge hashes strictly exclude system file paths, run timestamps, or platform-specific newline discrepancies.
4. **Zero Semantic Drift**: Prior phase knowledge schemas (P2.1 risk rules, P2.2 agility rules, P2.3 blast radius rules, P3 migration targets) remain 100% frozen with zero semantic drift.

---

## 2. Federated Manifest Topology

```
backend/knowledge/crypto_knowledge.yaml (v2024.1 Manifest)
├── algorithm_security.yaml        (Algorithms, aliases, roles, quantum impact, PQC status)
├── pqc_migration_knowledge.yaml   (PQC migration targets, hybrid KEX semantics)
├── protocol_security.yaml         (TLS version statuses, SSH legacy algorithms)
├── crypto_risk_rules.yaml         (Risk scoring rules & factors)
├── crypto_agility_rules.yaml      (7-dimension agility evaluation criteria)
├── blast_radius_rules.yaml        (Impact tiers, criticality indicators, graph exclusions)
├── crypto_sinks.yaml              (Polyglot API signatures & dependency capabilities)
└── binary_crypto_signatures.yaml  (Byte signatures, S-boxes, polynomial tables, OIDs)
```

---

## 3. Knowledge Base Version Lifecycle

1. **Manifest Validation**: `load_knowledge_version()` loads `crypto_knowledge.yaml`.
2. **Path Sanitization**: Sources are resolved strictly within `backend/knowledge/`, rejecting any relative path traversal (`..`) or absolute path specifications.
3. **Cryptographic Verification**: Each file's SHA-256 digest is computed and compared against `expected_sha256`.
4. **Metrics Aggregation**: Total algorithms, migration mappings, and rules are summed across the 8 verified files.
5. **Canonical Hashing**: Deterministic `knowledge_hash` is computed over sorted canonical metadata.

---

## 4. Upstream Integration

Every intelligence assessment emitted by ECDAT V4 embeds:
- `knowledge_base_version: "2024.1"`
- `knowledge_hash: <sha256>`
- `knowledge_sources_verified: true`

This guarantees end-to-end provenance and reproducible evaluation results across scans and deployments.
