# ECDAT V4 — P5 Temporal Intelligence Architecture

## 1. Executive Summary

The ECDAT V4 **M3 Temporal Intelligence Layer** builds directly upon the frozen foundations of P0–P4 to answer the central enterprise question:

> *"How has our cryptographic posture, quantum exposure, agility, and migration progress evolved over time across repeated scans?"*

M3 combines three tightly coupled subsystems into a unified temporal pipeline:
1. **P5.1 — Advanced Evidence Fusion**: Freshness evaluation, lineage tracking (supersession graphs), and multi-scan corroboration without mutating frozen `Evidence` records.
2. **P5.2 — Temporal Crypto Intelligence**: Deterministic asset key mapping, fine-grained change detection, asset timeline generation, and domain-specific delta evaluators (Risk, PQC, Agility, Migration).
3. **P5.3 — Continuous Crypto Posture**: A 7-dimensional non-scalar posture profile, directional trend tracking, and historical change detection.

```
+-------------------------------------------------------------------------+
|                           FROZEN FOUNDATIONS                            |
|  P0 Engine -> P1 Multimodal Evidence -> P2 Asset Graph & Risk Engine    |
|             -> P3 Migration Intelligence -> P4 Knowledge & Benchmark    |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  P5.1 ADVANCED EVIDENCE FUSION                          |
|   Freshness Evaluation | Lineage / Supersession | Multi-Scan Corroboration|
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  P5.2 TEMPORAL CRYPTO INTELLIGENCE                      |
|   Deterministic Keying | Change Detector | Asset Timelines | Deltas    |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                  P5.3 CONTINUOUS CRYPTO POSTURE                         |
|   7-Dimension Posture Profile | Directional Trend | Posture Pipeline    |
+-------------------------------------------------------------------------+
```

---

## 2. Architectural Integrity & Clean-Room Decoupling

In strict compliance with governance rules:
- **Zero Code Contamination**: All models, diff algorithms, and state machines are implemented cleanly from first principles.
- **Additive Design**: P0–P4 data models, evidence states, confidence scores, blast-radius graphs, and knowledge manifests remain 100% frozen.
- **Evidence Immutability**: Historical `Evidence` records are strictly immutable. Freshness states, supersessions, and corroborations are tracked through external lineage wrappers (`EvidenceLineage`, `MultiScanCorroboration`).
- **Cryptographic Provenance**: Every `TemporalComparison` and `PostureAssessment` computes a deterministic SHA-256 hash over its constituent contents.

---

## 3. Database Persistence Schema

The persistence layer (`backend/engine/asset_graph.py` and `backend/engine/scan_store.py`) provides SQLite/PostgreSQL storage for all temporal artifacts:

1. **`temporal_comparisons`**: Stores scan-to-scan comparison deltas, asset change lists, category counts, and verification hashes.
2. **`evidence_timelines`**: Stores historical timelines per asset, recording first-seen, last-seen, observation intervals, and TTL gap alerts.
3. **`posture_assessments`**: Stores 7-dimension posture evaluations per scan and per asset.
4. **`posture_changes`**: Stores comparative posture shifts, directional trends (`IMPROVED`, `DEGRADED`, `STABLE`), and dimensional diffs.

---

## 4. Benchmark Performance & Scalability

Benchmarked via `backend/benchmarks/benchmark_p5_temporal.py` across synthetic enterprise workloads:

| Workload ($N$) | Total Time (s) | Comparison Time (s) | Throughput (assets/sec) | Posture Latency (P50) | Peak Memory (MB) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **100 assets** | 0.1096 s | 0.0095 s | 912.09 assets/sec | 0.9708 ms | 0.66 MB |
| **1,000 assets** | 0.1933 s | 0.1132 s | 5,174.33 assets/sec | 0.6489 ms | 2.05 MB |
| **5,000 assets** | 0.6094 s | 0.5071 s | 8,204.94 assets/sec | 0.6407 ms | 9.31 MB |

### Key Observations:
- **Sub-Millisecond Posture Evaluation**: The 7-dimension posture classifier evaluates an asset in under 0.65 ms at P50.
- **Linear Scaling**: Scan comparison scales linearly with asset count ($O(N)$ with deterministic hash lookups).
- **Minimal Memory Overhead**: A 5,000-asset deep comparison uses under 10 MB of RAM.
