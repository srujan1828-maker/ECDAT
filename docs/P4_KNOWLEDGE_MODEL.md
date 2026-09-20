# ECDAT V4 — P4.1 Knowledge Base Data Model & Schema

## 1. Schema Definition

The versioned knowledge architecture is defined by the `KnowledgeBaseVersion` model in `backend/engine/knowledge_version.py`:

```python
@dataclass
class KnowledgeBaseVersion:
    knowledge_base_id: str             # Canonical identifier (e.g. 'ecdat-v4-crypto-knowledge')
    version: str                       # Version string (e.g. '2024.1')
    schema_version: str                # Manifest schema format version (e.g. '1.0.0')
    engine_version: str                # Compatible engine version (e.g. '4.0.0')
    knowledge_hash: str                # Deterministic SHA-256 over canonical source definitions
    rule_count: int                    # Aggregated count of rules, sinks, signatures
    algorithm_count: int               # Count of canonical cryptographic algorithms
    migration_mapping_count: int       # Count of PQC migration targets & hybrid semantics
    sources: List[Dict[str, Any]]      # Verified inventory of referenced YAML sources
    compatibility_notes: List[str]     # Scope, limitations, and deprecation notices
    provenance: Dict[str, Any]         # Maintainers, research methodology, standards references
```

---

## 2. Source Inventory (v2024.1)

| Source ID | File Name | Content Type | Version | Items Count | SHA-256 Digest |
|:---|:---|:---|:---:|:---:|:---|
| `algorithm_security` | `algorithm_security.yaml` | Algorithms & Aliases | 2024.1 | 32 | `d78dd6970536dc2e9b5b14556ec251fad6133f731f5f5f6449f64bc51d886096` |
| `pqc_migration_knowledge` | `pqc_migration_knowledge.yaml` | PQC Mappings | 2024.1 | 6 | `55997b2ccc053b060430f2d8f5864616e55d6d55a3ef5b77b8e25fce7adab4f2` |
| `protocol_security` | `protocol_security.yaml` | Protocol Rules | 2024.1 | 8 | `c2fdcc38a0e211a55360f56e921616f7f7674af115bab10f60072b8ae4070a9d` |
| `crypto_risk_rules` | `crypto_risk_rules.yaml` | Risk Rules | — | 15 | `078c64358b682c61bb93425def445bb05d502518edd6563a2279f75e59b20f8e` |
| `crypto_agility_rules` | `crypto_agility_rules.yaml` | Agility Rules | 2024.1 | 28 | `5cdf6296e3e32d03f3f166b70a2f4a25e454bc471e8ad3fa31ee7f57208d3199` |
| `blast_radius_rules` | `blast_radius_rules.yaml` | Blast Radius Rules | — | 20 | `c6605d6b5a8f890f03b9fb2fe700c4ba78bb171caf7342ea77a4df144da37f34` |
| `crypto_sinks` | `crypto_sinks.yaml` | API Sink Definitions | 4.0.0 | 39 | `7bee8f3624985e2a8ae6e60180c9a28632385c74f17e636cc2d7e349fec8ced4` |
| `binary_crypto_signatures` | `binary_crypto_signatures.yaml` | Binary Signatures | — | 21 | `3086de32a8204c7b9b471b2ce71f23a1f908cc2cf4c3a11d6a3a69f53a4df9df` |

**Aggregated Totals**:
- **Total Algorithms**: 32
- **Total Migration Mappings**: 6
- **Total Rules / Sinks / Signatures**: 131
- **Federated Knowledge Hash**: `a70014809f31d8f4eba4676d1031ce7a7154f7eb7fd0af5c5a2e66972e08ab4f`

---

## 3. External Standards Grounding

The knowledge base references:
- **NIST SP 800-57 Part 1 Rev. 5**: Cryptographic key management and algorithm transition lifecycles.
- **NIST FIPS 203**: ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism).
- **NIST FIPS 204**: ML-DSA (Module-Lattice-Based Digital Signature Standard).
- **NIST FIPS 205**: SLH-DSA (Stateless Hash-Based Digital Signature Standard).
- **NIST SP 800-131A Rev. 2**: Transitioning the use of cryptographic algorithms and key lengths.
- **IETF RFC 8996**: Deprecation of TLS 1.0 and TLS 1.1.
- **IETF RFC 8446**: The Transport Layer Security (TLS) Protocol Version 1.3.
