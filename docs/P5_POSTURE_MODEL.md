# ECDAT V4 — P5.3 Continuous Posture Model

## 1. Architectural Philosophy: The Non-Scalar Axiom

Traditional security posture tools attempt to boil entire cryptographic estates into a single 0–100 or letter-grade score. In enterprise cryptography, **scalar scores are fundamentally deceptive and dangerous**:
- A system could score "92/100" while harboring a single hardcoded RSA-1024 private key in its core banking transaction signing module.
- An increase in discovered inventory (better scanning coverage) might artificially lower a scalar score, penalizing the security team for improving visibility.

ECDAT V4 **strictly rejects scalar score collapse**. Instead, posture is represented as a **7-Dimensional Orthogonal Profile**:

$$\text{Posture} = \langle D_{\text{inv}}, D_{\text{risk}}, D_{\text{pqc}}, D_{\text{agility}}, D_{\text{blast}}, D_{\text{mig}}, D_{\text{evid}} \rangle$$

---

## 2. The 7 Orthogonal Dimensions

Each dimension operates as an independent state machine with explicit semantic boundaries:

| Dimension | Description | States | Key Metrics / Evidence |
| :--- | :--- | :--- | :--- |
| **1. CRYPTO_INVENTORY** | Completeness and volume of observed cryptographic assets. | `EMPTY`, `MINIMAL`, `CATALOGED`, `EXPANDING` | Total cataloged asset count, coverage spread. |
| **2. QUANTUM_RISK** | Exposure to Shor's and Grover's algorithm attacks. | `SAFE`, `LOW`, `MODERATE`, `HIGH`, `CRITICAL` | Max Mosca risk score, asymmetric vulnerability count. |
| **3. PQC_READINESS** | Transition toward NIST PQC FIPS standards. | `NON_PQC`, `TRANSITIONAL`, `HYBRID`, `PQC_NATIVE` | Ratio of ML-KEM, ML-DSA, SLH-DSA, and hybrid suites. |
| **4. CRYPTO_AGILITY** | Ease of algorithm and key replacement without code rebuild. | `HARDCODED`, `BRITTLE`, `MODERATE`, `AGILE` | Agility scores, configuration abstraction, decoupling. |
| **5. BLAST_RADIUS** | Potential downstream blast radius if compromised. | `ISOLATED`, `CONTAINED`, `MODERATE`, `HIGH`, `SYSTEMIC` | Graph dependent count, cross-boundary reach, path depth. |
| **6. MIGRATION_STATUS** | Execution progress of active PQC migration plans. | `NOT_STARTED`, `PLANNED`, `IN_PROGRESS`, `VERIFIED`, `BLOCKED` | Verified migration counts, blocked plans. |
| **7. EVIDENCE_QUALITY** | Fidelity and corroboration depth of underlying telemetry. | `SPECULATIVE`, `HEURISTIC`, `VERIFIED_STATIC`, `VERIFIED_RUNTIME`, `CORROBORATED` | Max evidence level (E0–E5), multi-modal corroboration. |

---

## 3. Directional Trend Evaluation

Posture transitions are evaluated comparatively across sequential scans:

- **`IMPROVED`**: Positive movement in one or more dimensions without degradation in others (e.g., Risk moved from `HIGH` to `LOW`, or PQC moved to `PQC_NATIVE`).
- **`DEGRADED`**: Negative movement in any critical dimension (e.g., introduction of new legacy algorithms, regression of agility).
- **`STABLE`**: No dimensional state changes between scans.
- **`DRIFTED`**: Mixed movement (some dimensions improved while others degraded; requires triage).
- **`NOT_ENOUGH_HISTORY`**: Explicit state assigned when only a single baseline scan exists.

### Single-Scan Baseline Rule
A single scan establishes the baseline posture profile. It is mathematically impossible to evaluate a historical trend with $N=1$ observations. Attempting to report "Trend: STABLE" or "Trend: IMPROVED" for a single scan is prohibited.
