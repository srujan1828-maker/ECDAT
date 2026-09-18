# ECDAT V4 — P5.2 Change Detection & Comparative Analytics

## 1. Overview

Comparing cryptographic inventories across discrete scans requires deterministic identity mapping. Naive comparisons based on database IDs or ephemeral memory addresses fail because new scan IDs are assigned on every run.

The **ECDAT V4 Change Detection Engine** provides:
1. **Deterministic Asset Key Computation**: Collision-resistant cryptographic key generation.
2. **Deep Property Diffing**: Multi-attribute difference detection.
3. **Domain-Specific Delta Evaluators**: Targeted delta semantics for Risk, PQC, Agility, and Migration.

---

## 2. Deterministic Asset Key Normalization

The `compute_asset_key(asset)` function derives a normalized key from invariant domain traits:
$$\text{AssetKey} = \text{SHA256}(\text{AssetType} \parallel \text{CanonicalAlgo} \parallel \text{KeySize} \parallel \text{PathContext} \parallel \text{CleanName})$$

- Strips ephemeral UUIDs and dynamic session tokens.
- Canonicalizes algorithm aliases (`aes_256_gcm` $\rightarrow$ `AES`).
- Normalizes deployment context (source file path, artifact ID, library name).

### Key Invariant:
When an asset's identity remains stable, parameter shifts (e.g. key length upgrade from 1024 to 2048) are detected as `CHANGED` rather than `REMOVED + ADDED`.

---

## 3. Change Categories

Every asset in a scan comparison is classified into exactly one category:
- **`ADDED`**: Asset exists in Target Scan B but was absent in Base Scan A.
- **`REMOVED`**: Asset existed in Base Scan A but was absent in Target Scan B.
- **`CHANGED`**: Asset exists in both scans, but one or more properties changed.
- **`UNCHANGED`**: Asset exists in both scans with identical properties.

### Deep Diff Attributes:
- `algorithm`: Primitive change (e.g. RSA $\rightarrow$ ML-KEM).
- `key_size`: Key length change (e.g. 1024 $\rightarrow$ 2048).
- `library`: Underlying implementation library change (e.g. OpenSSL 1.1 $\rightarrow$ OpenSSL 3.0).
- `version`: Implementation version change.
- `evidence_level`: Telemetry fidelity change (e.g. E1 static $\rightarrow$ E4 runtime).
- `fips_status`: Compliance certification change.

---

## 4. Domain-Specific Delta Evaluators

### 4.1 Temporal Risk Shifts
- `DOWNWARD`: Risk score decreased (vulnerability mitigated or key size upgraded).
- `UPWARD`: Risk score increased (deprecated algorithm introduced or weaker parameters).
- `NEUTRAL`: No risk score change.
- `FLAPPING`: Oscillating risk scores across successive scans.

### 4.2 Temporal PQC Shifts
- `CLASSICAL_TO_HYBRID`: Classical primitive wrapped in hybrid PQC scheme.
- `HYBRID_TO_PQC`: Hybrid scheme transitioned to pure native PQC standard.
- `CLASSICAL_TO_PQC`: Direct migration to native PQC (e.g. ML-KEM-768).
- `FIPS_UPGRADE`: Non-compliant primitive replaced by FIPS 203/204/205 standard.
- `PQC_DOWNGRADE`: PQC primitive removed in favor of classical algorithm.

### 4.3 Temporal Agility Shifts
- `AGILITY_IMPROVED`: Hardcoded constants replaced with configuration/factory abstractions.
- `AGILITY_DEGRADED`: Hardcoded parameters introduced.
- `AGILITY_UNCHANGED`: No shift in agility characteristics.

### 4.4 Temporal Migration Shifts
- `MIGRATION_ADVANCED`: Migration plan moved from `PLANNED` $\rightarrow$ `IN_PROGRESS` $\rightarrow$ `VERIFIED`.
- `MIGRATION_REGRESSED`: Verified migration failed re-verification.
- `MIGRATION_BLOCKED`: Migration execution blocked by downstream dependency conflict.
- `MIGRATION_UNCHANGED`: No change in migration status.
