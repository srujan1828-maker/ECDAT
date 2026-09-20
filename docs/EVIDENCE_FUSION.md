# ECDAT V4 — Evidence Fusion & Corroboration Engine

## 1. Multi-Modal Corroboration Overview

ECDAT V4 discovers cryptography across three disjoint observational modalities:
1. **Source Code Analysis (AST / Syntactic)**: Static inspection of function calls, class instantiations, and cryptographic constant parameters.
2. **Binary & Firmware Inspection (ELF / PE / Entropy)**: Disassembly symbols, cryptographic constants (S-Boxes, initialization vectors), and section entropy analysis.
3. **Network & Protocol Probing (Active TLS / Handshakes)**: Runtime cipher suite negotiation, certificate chain inspection, and ML-KEM post-quantum hybrid key share measurement.

When an asset is observed across multiple modalities, ECDAT V4 passes the evidence through the **`EvidenceFusionEngine`** to reconcile agreement, detect operational divergence, and calculate mathematically grounded confidence.

---

## 2. Evidence Fusion Algebra

### Promotion Rule
If an asset is verified by independent static ($E_2$) and dynamic ($E_3$) measurements without contradiction, its evidence level is promoted to:
$$\text{Level}(A) = E_4 \quad (\text{Multi-Modal Corroborated})$$

### Probabilistic Confidence Fusion
Assuming independent observations $O_1, O_2, \dots, O_n$ with error probabilities $(1 - C_i)$, the probability of at least one valid observation is:

$$C_{\text{fused}} = \min\left(0.99, \, 1 - \prod_{i=1}^n (1 - C_i)\right)$$

#### Example
- Observation 1 (Static AST): $C_1 = 0.80$
- Observation 2 (Active TLS Probe): $C_2 = 0.85$
$$C_{\text{fused}} = 1 - (1 - 0.80)(1 - 0.85) = 1 - (0.20 \times 0.15) = 1 - 0.03 = 0.97$$

---

## 3. Contradiction Detection

A **contradiction** occurs when multiple observations agree on the primary algorithm family (e.g., RSA) but report irreconcilable key sizes, curve parameters, or security modes.

### Real-World Contradiction Scenarios
- **Configuration Drift**: Source code explicitly requests `RSA-4096`, but the active TLS gateway negotiates a legacy `RSA-2048` certificate.
- **Dead Code**: Source code defines `X25519MLKEM768`, but runtime TLS probing proves the web server rejects post-quantum hybrid key exchange.

### Resolution Protocol
When a contradiction is detected:
1. The evidence state is explicitly updated to `EvidenceState.CONTRADICTED`.
2. The confidence score is penalized ($\max(C_i) - 0.20$ or bounded to a low certainty floor).
3. The discrepancy is documented in structured metadata (`discrepancies` list).
4. An actionable explanation is emitted:
   > *"Static analysis observed RSA with key size 4096, but dynamic network probing observed key size 2048 on endpoint."*

---

## 4. Deterministic "Why Was This Detected?" Explanation Engine

Every finding presents an auditable, human-readable breakdown explaining:
1. Which tools detected the asset and on which files/lines.
2. The exact cryptographic parameters observed (algorithms, key sizes, curves).
3. Why the evidence level and confidence were assigned.
4. Specific remediation or post-quantum upgrade recommendations.

### Example Explanation Output
```markdown
### Asset: RSA-2048 (Quantum Vulnerable)
- **Status**: Corroborated (Level: E4)
- **Confidence**: 97%
- **Why Was This Detected?**:
  1. Observed in source file `src/auth/jwt.py` at line 34 (AST call to `jwt.algorithms.RSAAlgorithm`).
  2. Observed in live TLS handshake probe against endpoint `api.service.internal:443` (Negotiated Cipher: `TLS_RSA_WITH_AES_256_GCM_SHA384`).
- **Post-Quantum Recommendation**:
  - Replace key establishment with **ML-KEM-768** (FIPS 203).
  - Replace signature authentication with **ML-DSA-65** (FIPS 204).
```
