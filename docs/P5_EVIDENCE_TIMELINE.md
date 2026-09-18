# ECDAT V4 — P5.1 & P5.2 Evidence Freshness, Lineage, and Timelines

## 1. Overview

Evidence in cryptographic posture management is inherently dynamic. Codebases evolve, keys rotate, dependencies are patched, and network configurations shift. 

The **Evidence Timeline Engine** addresses three critical requirements:
1. **Freshness Tracking**: Differentiating between actively corroborated observations and stale telemetry.
2. **Lineage & Supersession**: Capturing how and why an evidence item was replaced without deleting historical audit records.
3. **Multi-Scan Corroboration**: Evaluating whether findings are ephemeral anomalies or persistent structural patterns.

---

## 2. Evidence Freshness Taxonomy

Every evidence item's freshness is computed dynamically against an evaluation timestamp:

```
[Scan Time t0] ---------------- [Aging Threshold: 30d] ----------- [TTL: 90d] ------->
     |                                   |                                |
     v                                   v                                v
   FRESH                               AGING                            STALE (or EXPIRED)
```

- **`FRESH`**: Observed within the active window ($t \le 30\text{ days}$). Highly reliable for operational decisions.
- **`AGING`**: Approaching decay ($30\text{ days} < t \le 90\text{ days}$). Requires re-verification in subsequent scans.
- **`STALE`**: Observation exceeds standard TTL ($t > 90\text{ days}$). Must not be treated as current state without re-validation.
- **`EXPIRED`**: Exceeds maximum evidentiary retention window.
- **`UNSPECIFIED`**: No observation timestamp available in telemetry.

### Non-Mutating Guarantee
The frozen `Evidence` dataclass is never modified. Freshness is returned as an independent `EvidenceFreshness` assessment.

---

## 3. Evidence Lineage & Supersession

When an asset undergoes cryptographic remediation, new evidence supersedes old evidence:

```
+------------------------------------+
|  Old Evidence (ev-1)               |
|  Level: E3                         |
|  Algo: 3DES-168                    |
|  Status: SUPERSEDED                |
+------------------------------------+
                  |
                  | Superseded by (Reason: ALGORITHM_UPGRADE)
                  v
+------------------------------------+
|  New Evidence (ev-2)               |
|  Level: E4                         |
|  Algo: AES-256-GCM                 |
|  Status: ACTIVE                    |
+------------------------------------+
```

### Supported Supersession Reasons:
- `KEY_ROTATION`: Key updated or rotated while maintaining primitive structure.
- `ALGORITHM_UPGRADE`: Transition from legacy to modern/PQC primitive.
- `PARAMETER_CHANGE`: Key length, padding mode, or curve parameter adjusted.
- `REASSESSMENT`: High-fidelity observation (e.g. E4 runtime) superseding lower-fidelity heuristic (E1).

---

## 4. Multi-Scan Corroboration

Cross-scan corroboration measures stability across repeated scans:
- **`PERSISTENT_CORROBORATED`**: Observed consistently across multiple successive scans ($\ge 2$ scans, persistence ratio $\ge 0.8$).
- **`NEWLY_OBSERVED`**: First appearance in the most recent scan.
- **`EPHEMERAL`**: Appeared in a single intermediate scan and vanished (indicative of test scripts or ephemeral containers).
- **`INTERMITTENT`**: Flapping across scans with low persistence ratio ($< 0.5$).

---

## 5. Asset Historical Timeline

The `build_asset_timeline()` engine reconstructs the chronological journey of an asset across all recorded scans:

- **First Seen & Last Seen**: Earliest and latest verified observation timestamps.
- **Timeline Events**:
  - `FIRST_SEEN`: Initial discovery event.
  - `OBSERVED`: Re-observed in subsequent scan.
  - `CHANGED`: Structural algorithm or parameter modification.
  - `SUPERSEDED`: Evidence replaced by higher-level or remediated observation.
  - `STALE`: Time gap between observations exceeds TTL threshold.
  - `GAP_DETECTED`: Scanner outage or asset disappearance detected.
  - `RETIRED`: Asset completely absent from final scans.
