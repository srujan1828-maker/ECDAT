# ECDAT V4 — Cryptographic Asset Graph & Blast Radius

## 1. Overview & Architecture

The ECDAT V4 Cryptographic Asset Graph organizes observed cryptographic primitives, keys, certificates, libraries, protocols, and calling services into a directed relational dependency graph.

Rather than treating cryptographic findings as flat tables of isolated alerts, the asset graph establishes:
1. **Structural Context**: Which service or library calls a given algorithm or loads a given key.
2. **Blast Radius Analysis**: If an algorithm (e.g., `RSA-2048` or `ECDH-P256`) is broken or deprecated by NIST post-quantum standards, exactly which upstream services, libraries, and protocols fail or require migration.
3. **Cycle Invariance**: Secure traversal across complex recursive or circular dependencies.

---

## 2. Database Schema (`SQLite3`)

The asset graph is persisted with foreign key enforcement (`PRAGMA foreign_keys = ON;`) and WAL mode:

```sql
CREATE TABLE IF NOT EXISTS crypto_assets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    algorithm TEXT,
    key_size_bits INTEGER,
    curve TEXT,
    purpose TEXT,
    quantum_vulnerable INTEGER DEFAULT 1,
    pqc_replacement TEXT,
    scan_id TEXT NOT NULL,
    project TEXT NOT NULL,
    metadata JSON DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS graph_edges (
    id TEXT PRIMARY KEY,
    source_asset_id TEXT NOT NULL,
    target_asset_id TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    weight REAL DEFAULT 1.0,
    metadata JSON DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY (source_asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE,
    FOREIGN KEY (target_asset_id) REFERENCES crypto_assets(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
```

---

## 3. Node Types & Relationship Semantics

### Asset Types
- `algorithm`: Cryptographic primitive (e.g., `RSA`, `AES-GCM`, `ML-KEM-768`, `SHA-256`).
- `key`: Key material, session key, or public/private keypair.
- `certificate`: X.509 certificate or certificate authority chain.
- `protocol`: Transport or application protocol (e.g., `TLS 1.3`, `SSHv2`, `IPSec`).
- `library`: Cryptographic module or runtime provider (e.g., `OpenSSL 3.5.0`, `PyCryptodome`, `BouncyCastle`).
- `service`: Application service, endpoint, or binary executable calling cryptographic functions.
- `hardware`: HSM, TPM 2.0, or secure enclave module.

### Edge Relationship Types
- `uses`: A service or protocol uses a cryptographic asset.
- `calls`: A function or module invokes a cryptographic algorithm API.
- `negotiates`: A protocol handshake establishes or negotiates an algorithm or cipher suite.
- `protects`: A key or algorithm protects a data asset, payload, or channel.
- `wraps`: A key encryption key (KEK) wraps a data encryption key (DEK).
- `depends_on`: A module or library depends on an underlying crypto engine.
- `implements`: A library or hardware provider implements a cryptographic primitive.
- `configures`: A configuration file sets parameters (e.g., minimum TLS version or cipher list).

---

## 4. Blast Radius Traversal Algorithm

When an asset is compromised or deprecated, the blast radius is computed by **reverse dependency traversal**—identifying all nodes that depend directly or transitively on the target asset:

$$\text{BlastRadius}(A_0) = \{ v \in V \mid \exists \text{ path from } v \text{ to } A_0 \text{ in } G \}$$

### Algorithm Specification
```python
def get_blast_radius(self, asset_id: str) -> dict:
    visited = set()
    queue = deque([asset_id])
    affected_nodes = []
    direct_callers = []
    
    while queue:
        curr = queue.popleft()
        # Find all edges where target == curr (who calls curr?)
        incoming_edges = self.get_incoming_edges(curr)
        for edge in incoming_edges:
            caller_id = edge.source_asset_id
            if caller_id not in visited and caller_id != asset_id:
                visited.add(caller_id)
                queue.append(caller_id)
                affected_nodes.append(self.get_asset(caller_id))
                if curr == asset_id:
                    direct_callers.append(caller_id)
                    
    return {
        "target_asset": self.get_asset(asset_id),
        "blast_radius_count": len(visited),
        "affected_nodes": affected_nodes,
        "direct_callers": direct_callers,
        "quantum_risk_amplification": any(n.is_service for n in affected_nodes)
    }
```

---

## 5. REST API Endpoints

- `GET /api/scans/{scan_id}/graph`: Retrieve complete sub-graph for a specific scan job.
- `GET /api/graph?project=...`: Query global project graph with optional depth and type filtering.
- `GET /api/assets?project=...`: List all discovered cryptographic assets.
- `GET /api/assets/{asset_id}`: Retrieve single asset metadata, algorithm parameters, and PQC status.
- `GET /api/assets/{asset_id}/evidence`: Fetch all raw and fused evidence associated with the asset.
- `GET /api/assets/{asset_id}/relationships`: Retrieve incoming and outgoing graph edges.
- `GET /api/assets/{asset_id}/blast-radius`: Calculate the full blast radius and affected upstream systems.
