# ECDAT V4 — P5 Temporal Intelligence Limitations & Scope Boundaries

## 1. Multi-Scan Alignment & Identity Mapping Limits

- **Code Refactoring & Rename Blindspots**: Deterministic asset key calculation relies on canonical algorithm, key size, and path/deployment context. If a file is renamed (e.g. `auth/old_crypto.py` $\rightarrow$ `security/crypto_v2.py`) without source control metadata linkage, ECDAT classifies this as 1 `REMOVED` asset and 1 `ADDED` asset rather than a single continuous asset rename.
- **Dynamic Port & IP Flapping**: For network-observed cryptographic services, ephemeral port reassignment or dynamic cloud load balancer IP shifts may be classified as new network endpoints if hostnames or TLS SNI headers are not consistently present.

---

## 2. Temporal Synchronization & Clock Skew

- **Distributed Telemetry Clock Skew**: ECDAT relies on UTC ISO-8601 timestamps provided in scanner evidence. If distributed scanners or CI/CD runners experience unsynchronized clock drift exceeding several hours, scan order sequence may be distorted.
- **Out-of-Order Ingestion**: While `build_asset_timeline()` explicitly re-sorts scans chronologically by timestamp, real-time streaming ingestion must buffer events to prevent out-of-order state transitions.

---

## 3. TTL Thresholds & Policy Sensitivity

- **Heuristic Freshness Boundaries**: Default freshness thresholds (30 days for aging, 90 days for stale TTL) are enterprise conventions rather than absolute mathematical constants. Systems with continuous CI/CD deployments may require tighter TTLs (e.g. 7 days), while air-gapped embedded firmware systems may require multi-year TTLs.
- **Negative Evidence vs. Inactive Components**: If an asset is not observed in a scheduled scan, ECDAT marks it as `REMOVED` or records a timeline gap. This may indicate either true decommissioning or simply that a specific code path or test suite was skipped during that scan.

---

## 4. Posture Profile Scope Boundaries

- **Observed vs. Unobserved Cryptography**: The 7-dimensional posture profile reflects only observed and evidence-backed cryptography. It does not provide cryptographic assurance for closed-source proprietary third-party libraries where binary analysis could not extract cryptographic symbols.
- **No Predictive Guarantee of Zero-Days**: High agility or native PQC readiness reflects architectural preparedness against known Shor's and Grover's attack vectors, but does not guarantee immunity against novel cryptanalytic breakthroughs or implementation side-channel attacks.
