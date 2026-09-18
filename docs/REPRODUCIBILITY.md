# ECDAT V4 — Reproducibility, Manifests & Audit Verification

## 1. Reproducibility Mandate

A scan without an immutable manifest is unscientific and non-reproducible. In high-assurance cryptographic audits, security teams must be able to prove:
- Exactly what inputs were scanned.
- Which scanner versions and rules were active.
- What operating system, Python interpreter, OpenSSL version, and CPU hardware executed the scan.
- That identical inputs and environments yield bit-for-bit identical manifest hashes.

---

## 2. ScanManifest Schema

Every scan job automatically constructs a `ScanManifest`:

```python
@dataclass
class ScanManifest:
    manifest_version: str = "4.0.0"
    manifest_id: str = ""
    scan_id: str = ""
    project: str = "default"
    target_type: str = "source"  # source, binary, network
    target_inputs: list[dict] = field(default_factory=list)
    scanner_versions: dict[str, str] = field(default_factory=dict)
    environment: EnvironmentInfo = field(default_factory=EnvironmentInfo)
    policy_fingerprint: str = ""
    start_time: str = ""
    end_time: str = ""
    manifest_hash: str = ""
```

---

## 3. Canonical JSON & SHA-256 Fingerprinting

To guarantee that dictionary key ordering or whitespace differences across systems do not change the manifest digest, manifests use strict **Canonical JSON**:

```python
def canonical_json(data: Any) -> str:
    """Serializes data into deterministic JSON with sorted keys and no whitespace."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

def compute_sha256(canonical_str: str) -> str:
    """Computes prefixed SHA-256 digest: 'sha256:<hex>'."""
    return f"sha256:{hashlib.sha256(canonical_str.encode('utf-8')).hexdigest()}"
```

### Reproducibility Verification
1. Given identical `target_inputs`, `scanner_versions`, `environment`, and `policy_fingerprint`.
2. Construct the unhashed canonical JSON payload.
3. Compute the digest:
$$\text{Digest} = \text{SHA256}(\text{CanonicalJSON}(\text{Manifest}_{\text{unhashed}}))$$
4. Verify that `manifest.manifest_hash == Digest`.

---

## 4. Secret Scrubbing & Redaction

Scanners must never leak secrets, API credentials, or private cryptographic keys into stored manifests or log streams.

The `sanitize_secrets` engine inspects all dictionary fields and values:
- Scrubbed keys: `api_token`, `authorization`, `private_key`, `secret`, `password`, `bearer`.
- Replaced value: `"***REDACTED***"`
- Target inputs sanitize raw file paths containing usernames or environment secrets.

---

## 5. REST API Access

- `GET /api/scans/{scan_id}/manifest`: Retrieve the verified cryptographic manifest for any completed or running scan job.
