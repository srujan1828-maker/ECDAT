# ECDAT V4 — P4.2 Empirical Evaluation Results

> **Research Integrity Notice**: These benchmark results are derived from 736 deterministic synthetic controlled fixtures. They do not constitute a substitute for validation on production enterprise scan data.

## 1. Overall Performance Metrics

| Metric | Measured Value | Support |
|:---|:---:|:---:|
| **Total Test Cases** | 736 | 736 |
| **Precision** | **1.0000** | 412 / 412 |
| **Recall** | **0.8408** | 412 / 490 |
| **F1 Score** | **0.9135** | Harmonic Mean |
| **Accuracy** | **0.8940** | 658 / 736 |
| **True Positives (TP)** | 412 | — |
| **True Negatives (TN)** | 246 | — |
| **False Positives (FP)** | **0** | — |
| **False Negatives (FN)** | **78** | — |

---

## 2. Modality Performance Breakdown

| Modality | Total | TP | TN | FP | FN | Precision | Recall | F1 |
|:---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **NETWORK** | 142 | 90 | 52 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |
| **BINARY** | 135 | 60 | 35 | 0 | 40 | **1.0000** | 0.6000 | **0.7500** |
| **SOURCE** | 130 | 85 | 31 | 0 | 14 | **1.0000** | 0.8586 | **0.9239** |
| **DEPENDENCY** | 130 | 36 | 70 | 0 | 24 | **1.0000** | 0.6000 | **0.7500** |
| **X509** | 75 | 50 | 25 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |
| **PQC** | 74 | 56 | 18 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |
| **FIRMWARE** | 50 | 35 | 15 | 0 | 0 | **1.0000** | **1.0000** | **1.0000** |

---

## 3. False Negative Error Analysis

The evaluation observed **78 false negatives** across three specific modalities:
1. **Binary (40 FNs)**: Signatures where only partial S-boxes were embedded without defined symbol headers required for heuristic classification.
2. **Dependency (24 FNs)**: Manifests containing niche ecosystem libraries (e.g., custom npm/go modules) that are not yet cataloged in `crypto_sinks.yaml`.
3. **Source (14 FNs)**: Non-Python languages (e.g., Go/Rust/C++) containing novel custom wrapper APIs where static regex heuristics did not fire.

**Zero False Positives**:
ECDAT achieved 100% precision on the synthetic suite, correctly rejecting all 143 hard negative cases (imports without calls, dead code, commented APIs, advertised-only ciphers, untrusted certs, etc.).

---

## 4. Performance Scaling Benchmark

Measured on synthetic workloads ($N=100, 1000, 5000$):

| Workload ($N$) | Total Time | Throughput | P50 Latency | P95 Latency | Peak Memory |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **100** | 0.562 s | **177.89 cases/s** | 4.426 ms | 10.035 ms | 0.90 MB |
| **1,000** | 0.726 s | **1,377.74 cases/s** | 0.023 ms | 3.210 ms | 0.75 MB |
| **5,000** | 2.184 s | **2,289.85 cases/s** | 0.021 ms | 2.826 ms | 1.21 MB |

*Observed scaling was approximately linear over the tested fixture sizes.*
