# ECDAT — Master Implementation Guide
## Enterprise Cryptographic Discovery & Analysis Tool
### SIH 2026 | Problem Statement 26164 | NTRO | Blockchain & Cybersecurity

---

## CRITICAL CONTEXT FOR THE AI BUILDING THIS

You are completing and fixing an existing ECDAT codebase. The shell (sidebar, navigation, component files) largely exists. The core problem is **fake data, broken endpoints, disconnected components, and missing features.** Read this entire document before touching a single file.

**Tech Stack (do not change):**
- Frontend: Next.js (App Router), React 19, TypeScript, Tailwind CSS v4
- Backend: Python FastAPI, SQLite (WAL mode), background worker threads
- Key libraries: `sympy`, `pycryptodome`, `cryptography`, `httpx`, `py7zr`, `gitpython`, `PyGithub`

**Repository:** `github.com/srujan1828-maker/ECDAT`

---

## PART 1 — THE ABSOLUTE RULES (enforce everywhere, no exceptions)

### Rule 1: Zero Demo Data in Real Projects
Every new project starts completely empty:
```
Crypto Assets: 0
Evidence Items: 0
Scan Jobs: 0
Graph: 0 nodes, 0 edges
Risk findings: none
Migration plans: none
```
A controlled demo project (`id: "demo"`) MAY show pre-seeded data but MUST display a persistent `DEMO DATA` banner in amber on every panel. The demo project is read-only — no scans can be run on it. All other projects are real.

### Rule 2: Every Button Has a Real Backend Chain
```
UI Button → Frontend handler → API call → FastAPI route → Service layer → SQLite → Real result → UI state update
```
Never mock a response after the user clicks a real action button. If the backend service is not yet implemented, the button must show `NOT YET AVAILABLE` in a tooltip and be visually disabled — not fake-succeed.

### Rule 3: Network Scanner Returns Only What Was Observed
The current network scanner returns random confidence values and inferred cipher suites it never actually tested. This is WRONG and destroys credibility.
- If a cipher was not probed → result is `NOT_TESTED`, not `UNSUPPORTED` or `SUPPORTED`
- If a connection timed out → the TLS property is `UNKNOWN`
- If OpenSSL on the server does not support a PQC group → `UNAVAILABLE_ON_SCANNER` not `SERVER_DOES_NOT_SUPPORT`
- Confidence values must come from actual evidence quality, not random floats

### Rule 4: Graph Edges Cannot Exist Without Nodes
If `Crypto Assets = 0`, then `Graph Nodes = 0` AND `Graph Edges = 0`. If a scan produces 3 assets, the graph has at most 3 nodes. Never seed graph edges without the corresponding nodes existing in the database.

### Rule 5: Evidence Tier Drives Confidence
Every finding must carry an evidence level:
- `E0` = metadata only (dependency file listing)
- `E1` = heuristic (regex pattern match)
- `E2` = syntactic/AST (parsed source tree)
- `E3` = dynamic probe (actual TLS handshake, runtime trace)
- `E4` = corroborated across multiple surfaces
- `E5` = hardware attested (HSM, TPM)
Confidence is derived from this tier, not invented.

---

## PART 2 — ARCHITECTURE

```
frontend/src/
├── app/
│   ├── layout.tsx                    # Root: auth guard, theme provider
│   ├── page.tsx                      # → redirect to /login or /projects
│   ├── login/page.tsx                # Auth page
│   ├── register/page.tsx             # Registration
│   ├── projects/page.tsx             # Project list / create new
│   └── projects/[projectId]/
│       ├── page.tsx                  # Main workspace shell
│       └── changes/page.tsx          # Before/After diff hub
│
├── components/ecdat/
│   ├── project-shell.tsx             # Sidebar + header (already exists, needs fixes)
│   ├── overview.tsx                  # Executive Overview (needs real data binding)
│   ├── scan-studio.tsx               # Scan Studio (needs GitHub + large file support)
│   ├── scan-jobs.tsx                 # Scan Jobs list (needs real job polling)
│   ├── asset-inventory.tsx           # Asset table (needs real data)
│   ├── evidence-explorer.tsx         # Evidence drill-down (needs real data)
│   ├── crypto-graph.tsx              # Interactive graph (needs real nodes from DB)
│   ├── quantum-risk.tsx              # Quantum risk panel (needs real calculations)
│   ├── quantum-estimator.tsx         # Shor's resource estimator (interactive)
│   ├── mosca-hndl.tsx               # Mosca timeline (needs real project data)
│   ├── crypto-agility.tsx            # Agility assessment (needs real data)
│   ├── blast-radius.tsx              # Blast radius graph (needs real graph)
│   ├── auto-patch.tsx                # Patch engine panel
│   ├── migration-planner.tsx         # Migration planner (needs real assets)
│   ├── verification-engine.tsx       # Before/after verify
│   ├── standards-panel.tsx           # Compliance matrix
│   ├── runtime-ebpf.tsx              # Runtime tracer panel
│   ├── binary-pcap.tsx               # Binary ML + PCAP panel
│   ├── cbom-export.tsx               # CycloneDX export
│   ├── report-center.tsx             # Report generation
│   ├── secure-archive-lab.tsx        # Archive analysis + vault creation
│   └── custom-loop-panel.tsx         # One-click loop
│
backend/
├── main.py                           # FastAPI app, routes registration
├── engine/
│   ├── source_scan.py                # Python AST + polyglot regex scanner
│   ├── binary_deep.py                # ELF/PE/Mach-O + entropy
│   ├── archive_scanner.py            # ZIP/7z self-encryption detection (NEW)
│   ├── network_prober.py             # TLS prober (MUST BE REWRITTEN — see Part 5)
│   ├── github_scanner.py             # GitHub repo integration (NEW)
│   ├── quantum_risk.py               # Grover/Shor classification
│   ├── mosca.py                      # Mosca's theorem (NEW — use code in PROJECT.md)
│   ├── blast_radius.py               # BFS reverse dependency
│   ├── agility_engine.py             # Crypto agility dimensions
│   ├── migration_planner.py          # Dependency-aware migration
│   ├── cbom_generator.py             # CycloneDX 1.6 CBOM
│   ├── verifier.py                   # Before/after comparison
│   ├── patch_engine.py               # AST migration patches
│   ├── knowledge_graph.py            # Asset graph builder
│   └── quantum_estimator.py          # Shor's qubit resource estimator
├── models/
│   └── db.py                         # SQLAlchemy models
├── routes/
│   ├── scans.py                      # All scan endpoints
│   ├── assets.py                     # Asset endpoints
│   ├── quantum.py                    # Quantum analysis endpoints
│   ├── migration.py                  # Migration + verification
│   ├── export.py                     # CBOM + reports
│   └── archive.py                    # Secure Archive Lab
└── tests/
```

---

## PART 3 — EVERY SIDEBAR FEATURE: COMPLETE SPECIFICATION

### 3.1 EXECUTIVE OVERVIEW

**Purpose:** Single-screen answer to "What is our cryptographic security posture right now?"

**Inputs (from backend):** All data comes from `GET /api/overview?project={id}`

**Backend returns:**
```json
{
  "project_id": "string",
  "is_demo": false,
  "summary": {
    "total_crypto_assets": 0,
    "quantum_relevant_count": 0,
    "hndl_exposure_count": 0,
    "hybrid_pqc_capable_count": 0,
    "completed_scans": 0,
    "last_scan_at": null,
    "posture_score": null
  },
  "risk_distribution": {
    "critical_shor": 0,
    "high_grover": 0,
    "legacy_insecure": 0,
    "safe_pqc": 0,
    "unknown": 0
  },
  "algorithm_distribution": [],
  "discovery_coverage": {
    "source_ast": "NOT_SCANNED",
    "dependencies": "NOT_SCANNED",
    "binary_sections": "NOT_SCANNED",
    "firmware": "NOT_SCANNED",
    "live_network": "NOT_SCANNED",
    "x509_certs": "NOT_SCANNED",
    "archive_lab": "NOT_SCANNED",
    "pcap_stream": "NOT_SCANNED",
    "runtime_call": "NOT_SCANNED"
  },
  "action_queue": [],
  "mosca_top_risk": null,
  "recent_scans": []
}
```

**Frontend behavior:**
- If `summary.total_crypto_assets === 0` AND `is_demo === false`: show empty state with "Run your first discovery scan" CTA linking to Scan Studio. Do NOT show charts with zero data — charts only render when data exists.
- Metric cards at top show real counts from the summary object
- Risk distribution donut only renders if at least one asset exists
- Algorithm distribution bars only render if algorithms array is non-empty
- Coverage grid shows the status string for each surface — status strings are `NOT_SCANNED | SCANNED | SCANNING | BOUNDED | SUPPORTED | ACTIVE | UNMEASURED`
- Action Queue: generated server-side from real asset data — never hardcoded on frontend
- `posture_score` is `null` until at least one scan completes; display "—" instead of a number

**Dashboard Quantum Prediction Section (NEW):**
Add a new section below the action queue called "Quantum Risk Timeline." It shows:
- A horizontal bar chart: each row is one discovered algorithm family, the bar shows estimated years until quantum threat (Z value from Mosca engine). Color: green (>15yr) → amber (5-15yr) → red (<5yr).
- Only renders when assets exist.
- Data from `GET /api/quantum/timeline-summary?project={id}` which aggregates Mosca Z values per algorithm.

**Current bugs to fix:**
- The subtitle "Controlled demonstration project showcasing..." appears on ALL projects. It must only appear on the `demo` project.
- Metric counts must come from the database, not be hardcoded as 16/5/5/1/10.
- The action queue items must be generated from real scan evidence.

---

### 3.2 AUTONOMOUS CUSTOM LOOP

**Purpose:** One-click pipeline that runs discovery → CBOM → patch → verify on a chosen target. The entire loop is orchestrated by the backend. Frontend just starts it and polls for progress.

**Inputs:** User selects a target type and provides the target. Options:
- Python source file (upload .py file)
- C/C++ source file (upload .c/.h/.cpp file)
- Compiled binary (upload ELF/PE)
- GitHub repository URL (NEW)
- Project folder ZIP (upload ZIP of source)

**Backend endpoint:** `POST /api/custom-loop/run`
```json
{
  "project_id": "string",
  "target_type": "python_source | c_source | binary | github_repo | source_zip",
  "target": "file_id or github_url",
  "loop_options": {
    "run_patch": true,
    "run_tests": true,
    "run_verify": true
  }
}
```

**Backend process (all real, no mocks):**
```
1. Source scan → raw EvidenceRecord list (real scanner)
2. CBOM generation → CycloneDX 1.6 JSON (real cbom_generator.py)
3. Mosca risk assessment → per-algorithm risk scores
4. Patch generation → deterministic AST replacements (patch_engine.py)
   - Only replaces known-weak patterns: MD5→SHA-256, DES→AES-256-GCM, RSA-1024 key gen, ECB mode
   - Generates unified diff file
   - Generates test script
5. Test execution → subprocess in sandbox, timeout 30s, memory limit 256MB
6. Closed-loop verification → compare pre/post evidence records
7. Store all results with the loop_run_id
```

**Poll endpoint:** `GET /api/custom-loop/{run_id}/status`
```json
{
  "run_id": "string",
  "status": "running | completed | failed | partial",
  "current_step": 3,
  "total_steps": 7,
  "steps": [
    {"name": "Discovery Scan", "status": "completed", "assets_found": 8, "duration_ms": 2341},
    {"name": "CBOM Generation", "status": "completed", "duration_ms": 412},
    {"name": "Mosca Assessment", "status": "completed", "critical_count": 3},
    {"name": "Patch Creation", "status": "running"},
    {"name": "Test Execution", "status": "pending"},
    {"name": "Verification", "status": "pending"},
    {"name": "Report", "status": "pending"}
  ],
  "error": null
}
```

**Results endpoint:** `GET /api/custom-loop/{run_id}/results`

**Frontend:**
- Step progress shown as a vertical stepper (not a spinner — show each step with icon + status)
- Each step card expands to show detailed output when clicked
- "View Changes" button appears only when step 4 completes — links to `/projects/{id}/changes?loop={run_id}`
- Failed steps show the exact error message and a "Retry from this step" button

---

### 3.3 SCAN STUDIO

**Purpose:** The entry point for all discovery. Users configure and launch scans. This is the most important input surface.

**Supported scan surfaces and their inputs:**

#### Surface A: Source Code
- **Input types:**
  1. Single file upload (any supported language: .py, .java, .c, .cpp, .h, .go, .js, .ts, .rs)
  2. ZIP/tar.gz of source tree (up to 500MB — requires chunked upload)
  3. GitHub repository URL (public or private with token) — **NEW**
  4. Paste raw source code (max 50KB, textarea)
- **Backend:** `POST /api/scan/sources` (existing), extended with GitHub + chunked upload

#### Surface B: Dependencies
- **Input:** Upload dependency manifest files — `package.json`, `requirements.txt`, `Pipfile.lock`, `poetry.lock`, `pom.xml`, `build.gradle`, `go.mod`, `Cargo.toml`
- **Multiple files at once** (select multiple in file picker)
- **Backend:** `POST /api/scan/dependencies` — analyzes declared libraries, maps to known crypto libraries, returns inventory (not vulnerability analysis — just what crypto libs are declared)

#### Surface C: Binary / Firmware
- **Input:** Upload binary file — ELF, PE/COFF, Mach-O, raw firmware blob, ZIP of mixed binaries
- **Size limit:** 100MB per file, chunked upload for >10MB
- **Backend:** `POST /api/scan/binary` (existing) — entropy heatmap, section analysis, crypto signature matching

#### Surface D: Network / TLS Endpoint
- **Input:** Hostname or URL (must be user-authorized — show checkbox "I confirm I am authorized to scan this endpoint")
- **Backend:** `POST /api/scan/network` — MUST be the rewritten scanner (see Part 5)
- **NOT supported:** Scanning internal private IPs without explicit ECDAT_ALLOWED_CIDRS configured

#### Surface E: X.509 Certificate
- **Input:** Upload PEM/DER/P12 file, or paste PEM text, or enter domain to fetch live certificate
- **Backend:** `POST /api/scan/certificate` — parse cert, extract key algorithm/size/expiry/chain, evaluate quantum risk

#### Surface F: Archive
- **Input:** Upload ZIP, 7z, or other archive
- **Optionally provide password** (for encrypted archives — user must own and authorize)
- **Backend:** `POST /api/scan/archive` — detect encryption type on archive itself + content crypto discovery

#### Surface G: GitHub Repository (NEW)
- **Input:** GitHub URL (`https://github.com/owner/repo` or `https://github.com/owner/repo/tree/branch`)
- **Optional:** Personal Access Token for private repos (stored in session only, never persisted to DB)
- **Optional:** Branch selector (fetched after URL validated), subdirectory filter
- **Backend:** `POST /api/scan/github`

**GitHub backend implementation (`backend/engine/github_scanner.py`):**
```python
import os, tempfile, subprocess, shutil
from pathlib import Path
from github import Github, GithubException
import gitpython  # use gitpython for clone

SUPPORTED_EXTENSIONS = {'.py','.java','.c','.cpp','.h','.go','.js','.ts','.rs','.cs','.rb','.php'}
MAX_FILE_SIZE_BYTES = 500 * 1024  # 500KB per file (skip larger — log as skipped)
MAX_TOTAL_FILES = 2000
MAX_REPO_SIZE_MB = 500

def scan_github_repo(repo_url: str, token: str | None, branch: str | None, project_id: str) -> dict:
    """
    Clone the repo to a temp dir, iterate source files, run source_scan on each,
    aggregate evidence records, clean up temp dir.
    """
    tmpdir = tempfile.mkdtemp(prefix="ecdat_github_")
    try:
        # Authenticated clone if token provided
        if token:
            auth_url = repo_url.replace("https://", f"https://{token}@")
        else:
            auth_url = repo_url
        
        # Clone with depth=1 (no full history needed for source scan)
        clone_cmd = ["git", "clone", "--depth", "1", "--single-branch"]
        if branch:
            clone_cmd += ["--branch", branch]
        clone_cmd += [auth_url, tmpdir]
        
        result = subprocess.run(clone_cmd, capture_output=True, timeout=120, text=True)
        if result.returncode != 0:
            return {"error": f"Clone failed: {result.stderr[:500]}"}
        
        # Walk files
        evidence_records = []
        files_scanned = 0
        files_skipped = 0
        
        repo_path = Path(tmpdir)
        for file_path in repo_path.rglob("*"):
            if file_path.is_dir():
                continue
            if files_scanned >= MAX_TOTAL_FILES:
                files_skipped += 1
                continue
            if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
                continue
            if file_path.stat().st_size > MAX_FILE_SIZE_BYTES:
                files_skipped += 1
                continue
            # Skip vendor/node_modules/dist dirs
            rel = file_path.relative_to(repo_path)
            if any(part in {'node_modules','vendor','.git','dist','build','__pycache__'} for part in rel.parts):
                continue
            
            try:
                source_text = file_path.read_text(errors='replace')
                # Run existing source scanner
                from engine.source_scan import scan_source_text
                records = scan_source_text(
                    source=source_text,
                    filename=str(rel),
                    language=_detect_language(file_path.suffix)
                )
                evidence_records.extend(records)
                files_scanned += 1
            except Exception as e:
                files_skipped += 1
        
        return {
            "files_scanned": files_scanned,
            "files_skipped": files_skipped,
            "evidence_records": evidence_records,
            "repo_url": repo_url,
            "branch": branch or "default"
        }
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
```

**Chunked Upload for Large Files:**
- Frontend: use `multipart/form-data` with chunking library (e.g. `upchunk` or plain `Blob.slice`)
- Each chunk: `POST /api/upload/chunk` with headers `X-Upload-ID`, `X-Chunk-Index`, `X-Total-Chunks`, `X-Filename`
- Backend assembles chunks in temp storage, then triggers the appropriate scanner when `X-Chunk-Index === X-Total-Chunks - 1`
- Progress shown in Scan Studio as a progress bar (not a spinner)
- Max 500MB total

**Scan Studio UI layout:**
```
┌─────────────────────────────────────────────────────┐
│  NEW SCAN                              [Project: X]  │
├─────────────────────────────────────────────────────┤
│  SELECT SURFACE:                                     │
│  [Source Code] [Dependencies] [Binary] [Network]    │
│  [Certificate] [Archive]  [GitHub Repo] (tabs)      │
├─────────────────────────────────────────────────────┤
│  [Surface-specific input area]                      │
│                                                     │
│  SOURCE CODE surface:                               │
│  ┌──────────────────────────┐                       │
│  │  Drop files here or      │  [Browse]             │
│  │  paste GitHub URL        │  [Paste Code]         │
│  └──────────────────────────┘                       │
│  Supported: .py .java .c .go .js .ts .rs .cs .rb   │
│  Max size: 500MB (chunked upload)                   │
│                                                     │
│  GITHUB REPO surface:                               │
│  URL: [https://github.com/owner/repo        ]       │
│  Branch: [main ▼]  (fetched after URL validated)    │
│  Token: [optional for private repos       ]  🔒     │
│  Subdirectory: [optional filter           ]         │
├─────────────────────────────────────────────────────┤
│  Project: [Default System ▼]                        │
│  ☑ I confirm I am authorized to scan this target    │
│                          [Start Scan] [Save Config] │
└─────────────────────────────────────────────────────┘
```

---

### 3.4 SCAN JOBS

**Purpose:** List of all scan jobs for the current project, with real-time status.

**Backend:** `GET /api/scans?project={id}&limit=50&offset=0`

**Each job in the list:**
```json
{
  "id": "uuid",
  "surface": "source | github | binary | network | certificate | archive | dependencies",
  "input_summary": "main.py (3.2 KB) | github.com/owner/repo | example.com",
  "status": "queued | running | completed | failed | cancelled",
  "assets_found": 8,
  "evidence_count": 23,
  "started_at": "ISO timestamp",
  "completed_at": "ISO timestamp | null",
  "duration_ms": 2341,
  "error_summary": null
}
```

**Clicking a job opens a detail drawer (not a new page) showing:**
- Full configuration (input hash, scanner version, rule version)
- Stage-by-stage timing
- Full log output (scrollable, monospace, color-coded by severity)
- Evidence records produced (count, link to Evidence Explorer filtered by this job)
- Assets created/updated by this job
- Error detail if failed — with specific actionable message, not generic "scan failed"
- Retry button (for failed jobs)
- Cancel button (for queued/running jobs)

**Status polling:** While any job is `running`, poll `GET /api/scans/{id}` every 2 seconds. Show a subtle pulse animation on the status badge. Stop polling when status is terminal.

---

### 3.5 ASSET INVENTORY

**Purpose:** The authoritative table of all crypto assets discovered in the project.

**Backend:** `GET /api/assets?project={id}&filter[surface]=...&filter[risk]=...&filter[algorithm]=...&sort=risk_score&page=1&per_page=50`

**Each asset:**
```json
{
  "id": "uuid",
  "algorithm": "RSA",
  "key_size": 2048,
  "role": "KEY_ENCAPSULATION | SIGNATURE | SYMMETRIC_ENCRYPTION | HASH | MAC | KDF | PROTOCOL | CERTIFICATE | UNKNOWN",
  "surface": "source | binary | network | certificate | ...",
  "location": "auth_service.py:284 | 0x1A2F4 (ELF .text) | api.example.com:443",
  "evidence_level": "E0 | E1 | E2 | E3 | E4 | E5",
  "confidence": 0.94,
  "quantum_risk": "SHOR_VULNERABLE | GROVER_WEAKENED | LEGACY_BROKEN | SAFE | UNKNOWN",
  "mosca_score": 1.7,
  "mosca_verdict": "CRITICAL | AT_RISK | MONITOR | SAFE",
  "pqc_replacement": "ML-KEM-768 (FIPS 203)",
  "scan_id": "uuid",
  "discovered_at": "ISO timestamp"
}
```

**UI features:**
- Filterable by surface, risk level, algorithm family, evidence level
- Sortable by risk score, algorithm, surface, date
- Each row has: color-coded risk badge, algorithm pill, surface icon, evidence tier badge, Mosca score
- Click row → asset detail drawer with: full evidence, Mosca analysis, recommended migration, affected blast radius
- Bulk select → export selected to CBOM
- Empty state: "No crypto assets discovered yet. Run a scan from Scan Studio."

---

### 3.6 EVIDENCE EXPLORER

**Purpose:** Raw evidence inspection — the "show your work" view. Every finding, every scan, every confidence score, fully traceable.

**Backend:** `GET /api/evidence?project={id}&asset_id=...&scan_id=...&surface=...&level=...`

**Each evidence item:**
```json
{
  "id": "uuid",
  "asset_id": "uuid",
  "surface": "source",
  "evidence_type": "AST_API_CALL | REGEX_PATTERN | BINARY_SIGNATURE | TLS_NEGOTIATION | CERTIFICATE_FIELD | ENTROPY_ZONE | DEPENDENCY_DECLARATION",
  "evidence_level": "E2",
  "algorithm": "RSA",
  "cryptographic_role": "SIGNATURE",
  "location": "auth_service.py",
  "line_number": 284,
  "snippet": "key = RSA.generate(2048)",
  "rule_id": "PY-RSA-GEN-001",
  "rule_version": "2.1.0",
  "scanner_version": "ecdat-source-v2.1.0",
  "input_hash": "sha256:abc123...",
  "confidence": 0.94,
  "observed_value": "RSA.generate(2048)",
  "timestamp": "ISO"
}
```

**UI features:**
- Filter by surface, evidence level (E0–E5), algorithm, scan job
- Each row shows the snippet with syntax-highlighted code inline
- Source evidence shows file:line with the actual code snippet
- Binary evidence shows hex offset + surrounding bytes
- Network evidence shows the exact TLS handshake values observed
- "Why this confidence?" tooltip explains the evidence tier contribution
- Never show confidence values as percentages without explaining the basis

---

### 3.7 CRYPTO GRAPH

**Purpose:** Interactive force-directed graph of cryptographic assets and their relationships.

**Backend:** `GET /api/graph?project={id}` returns:
```json
{
  "nodes": [
    {
      "id": "asset_uuid",
      "label": "RSA-2048",
      "type": "ALGORITHM | APPLICATION | LIBRARY | CERTIFICATE | ENDPOINT | BINARY | DATA_FLOW",
      "risk_level": "CRITICAL | HIGH | MEDIUM | SAFE | UNKNOWN",
      "evidence_count": 4,
      "blast_radius_count": 3
    }
  ],
  "edges": [
    {
      "source": "node_id",
      "target": "node_id",
      "relationship": "USES | IMPLEMENTS | DEPENDS_ON | SERVES | AUTHENTICATED_BY | PROTECTS | CALLS",
      "confidence": 0.87,
      "evidence_id": "uuid"
    }
  ]
}
```

**Implementation:** Use `react-force-graph-2d` (lightweight, 2D, performant) or `cytoscape.js` — NOT Three.js for the graph (too heavy for 100+ node graphs). Three.js is reserved for the Quantum Lab visualizations.

**UI features:**
- Zoom/pan with mouse
- Click node → detail drawer (same component as Asset Inventory drawer)
- Click edge → show relationship evidence
- Filter by: risk level (hides safe nodes), surface, node type
- "Fit to screen" button
- Color: red = SHOR_VULNERABLE, amber = GROVER_WEAKENED, orange = LEGACY_BROKEN, green = SAFE, gray = UNKNOWN
- Node size = blast_radius_count (larger = more dependents)
- Legend always visible

**CRITICAL BUG TO FIX:** If `nodes` array is empty, graph shows only the empty canvas with a message "No assets to graph yet. Run a scan." If `edges` exist but reference node IDs not in the nodes array, those edges are silently dropped — never render orphan edges.

---

### 3.8 QUANTUM RISK

**Purpose:** Detailed breakdown of quantum exposure across all project assets, organized by attack type.

**Backend:** `GET /api/quantum/risk-summary?project={id}`
```json
{
  "shor_vulnerable": {
    "count": 5,
    "assets": ["uuid1", "uuid2"],
    "attack_explanation": "Shor's algorithm (1994) runs on a quantum computer in polynomial time to factor integers and solve discrete logarithm. It completely breaks RSA, ECDSA, ECDH, DSA, and DH. No classical defense exists against a CRQC running Shor's.",
    "algorithms_affected": ["RSA-2048", "ECC-P256", "ECDH-X25519"]
  },
  "grover_weakened": {
    "count": 2,
    "assets": ["uuid6", "uuid7"],
    "attack_explanation": "Grover's algorithm provides a quadratic speedup for unstructured search. For symmetric cryptography, this halves the effective security bits. AES-128 → 64-bit quantum security (below NIST PQC minimum of 128-bit).",
    "algorithms_affected": ["AES-128", "SHA-256 (truncated)"]
  },
  "legacy_broken": {
    "count": 1,
    "assets": ["uuid8"],
    "attack_explanation": "Classically broken — no quantum computer needed. These algorithms have published classical attacks.",
    "algorithms_affected": ["MD5"]
  },
  "safe_pqc": {
    "count": 1,
    "assets": ["uuid9"],
    "algorithms_affected": ["ML-KEM-768"]
  }
}
```

**UI:** Four sections, each expandable. Each algorithm in the "affected" list shows a pill that links to the filtered Asset Inventory. The explanations are shown as readable prose, not just labels.

---

### 3.9 QUANTUM ESTIMATION (Shor's Resource Simulator)

**Purpose:** Interactive tool showing how many qubits and how much time a quantum computer would need to break a specific key. Educational + evidence-based.

**Backend:** `POST /api/quantum/estimate-shor`
```json
{
  "algorithm": "RSA",
  "key_size_bits": 2048,
  "physical_error_rate": 0.001,
  "surface_code_distance": 23
}
```

**Backend returns:**
```json
{
  "algorithm": "RSA-2048",
  "logical_qubits": 4098,
  "physical_qubits_required": 4098000,
  "toffoli_gates": 2.3e12,
  "estimated_runtime_hours": 8.0,
  "surface_code_distance": 23,
  "physical_error_rate": 0.001,
  "current_largest_qc": "IBM Heron r2: 2000 physical qubits (2024)",
  "feasibility_today": "NOT_FEASIBLE",
  "estimated_feasibility_year": 2033,
  "reference": "Gidney & Ekerå, 2021. How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits.",
  "assumptions": [
    "Surface code error correction",
    "Physical error rate matches input",
    "No algorithmic improvements beyond Gidney-Ekerå"
  ]
}
```

**UI:** Interactive sliders for `key_size_bits` (512–16384), `physical_error_rate` (0.0001–0.01), `surface_code_distance` (7–31). Results update on slider change (debounced 300ms). Show a simple comparison chart: current IBM machine vs required qubits. This is NOT a demo — it calls the real backend.

**Also include the Shor's Live Demo (from PROJECT.md):**
A secondary section in this panel:
- "Generate Demo RSA-512 Keypair" button → `POST /api/quantum/shor-demo`
- Shows: N = P × Q breakdown, encrypted message, factoring animation (frontend animation, backend does the math)
- Decrypted message appears when factoring completes
- This uses REAL RSA-512 factoring via sympy on the backend — not a simulation

---

### 3.10 MOSCA & HNDL

**Purpose:** Apply Mosca's Theorem to every discovered asset and show which data is at risk of "Harvest Now, Decrypt Later."

**Backend:** `POST /api/quantum/mosca-project-scan` (auto-runs when panel opens)
Returns array of MoscaResult per unique algorithm found in the project.

**Interactive controls:**
- Global X slider: data sensitivity lifetime (1–50 years, default from project settings if set)
- Global Z override: "Quantum threat horizon assumption" (5–20 years, default from NTRO estimates)
- Y is calculated per-algorithm from estimated migration effort

**Mosca Timeline visualization:**
For each algorithm in the project:
```
Algorithm: RSA-2048
X ████████████████████████░░  25yr data lifetime
Y     ████████░░░░             3yr migration time (auto from blast radius)
Z          ████████████        10yr quantum threat window
           ↑ X+Y(28) > Z(10): AT RISK

Verdict badge: [AT RISK] [HNDL risk: adversaries may harvest today]
```

**HNDL Section:**
A separate sub-section below Mosca. Lists every asset where:
- quantum_risk = SHOR_VULNERABLE or GROVER_WEAKENED
- AND mosca verdict = CRITICAL or AT_RISK
- AND the asset is on a network surface (interceptable by adversary)

For each HNDL risk:
- Asset name, algorithm, location
- "Window of exposure" = estimated years until quantum break
- "Harvest start year" = TODAY (adversaries collect encrypted traffic NOW)
- "Data exposed if not migrated by" = current year + Z - Y
- Recommendation: immediate priority migration

---

### 3.11 CRYPTO AGILITY

**Purpose:** For each discovered cryptographic role, assess how hard it would be to replace the algorithm. This is the "migration difficulty" analysis.

**Backend:** `GET /api/agility/assessment?project={id}`

**Agility dimensions per asset:**
```json
{
  "asset_id": "uuid",
  "algorithm": "RSA-2048",
  "dimensions": {
    "algorithm_agility": "SUPPORTED",
    "configuration_agility": "PARTIALLY_OBSERVED",
    "dependency_agility": "CONSTRAINED",
    "protocol_agility": "UNKNOWN",
    "certificate_agility": "SUPPORTED",
    "deployment_agility": "BLOCKED",
    "validation_agility": "NOT_APPLICABLE"
  },
  "overall_score": 45,
  "migration_complexity": "HIGH",
  "blockers": ["HSM firmware does not support ML-KEM", "Client library locked to RSA"],
  "evidence_basis": "E2"
}
```

**Status values and their meanings (shown as tooltips):**
- `SUPPORTED` = evidence shows this dimension supports replacement
- `OBSERVED` = observed in evidence, not fully characterized
- `PARTIALLY_OBSERVED` = some evidence, gaps remain
- `CONSTRAINED` = can be replaced but with significant constraints
- `BLOCKED` = a hard dependency prevents replacement
- `UNKNOWN` = insufficient evidence to assess
- `NOT_APPLICABLE` = this dimension doesn't apply to this asset
- `SCANNER_UNAVAILABLE` = the scanner cannot measure this

**UI:** A table with assets as rows, agility dimensions as columns, color-coded cells. Sort by overall score. Click cell → tooltip with evidence basis.

---

### 3.12 BLAST RADIUS

**Purpose:** If asset X needs to be replaced, what breaks? Reverse-dependency BFS traversal of the crypto asset graph.

**Backend:** `GET /api/assets/{id}/blast-radius`
```json
{
  "root_asset_id": "uuid",
  "root_algorithm": "RSA-2048",
  "direct_consumers": [
    {"id": "uuid", "type": "APPLICATION", "label": "Auth Service", "confidence": 0.92}
  ],
  "transitive_consumers": [
    {"id": "uuid", "type": "APPLICATION", "label": "Payment Gateway", "depth": 2}
  ],
  "affected_certificates": 3,
  "affected_services": 5,
  "affected_data_flows": 2,
  "max_depth": 4,
  "total_affected_nodes": 11,
  "migration_complexity_estimate": "HIGH"
}
```

**UI:** Visual BFS tree starting from the selected asset, expanding outward by depth level. Nodes colored by type (application=blue, certificate=amber, data_flow=green). Click any node to navigate to that asset. "Select all in blast radius" button for CBOM export.

**If graph has no nodes:** Show "Run a discovery scan to build the asset graph. Blast radius requires graph edges from evidence." — not an error state.

---

### 3.13 AUTO PATCH ENGINE

**Purpose:** Generate deterministic, safe code patches that replace identified weak algorithms with PQC-safe alternatives.

**Backend:** `POST /api/patch/generate`
```json
{
  "scan_id": "uuid",
  "asset_ids": ["uuid1", "uuid2"],
  "patch_options": {
    "python": {"hash_md5_to": "SHA256", "aes128_to": "AES256", "rsa_to": "mlkem768"},
    "c": {"openssl_md5_to": "SHA256", "rsa_keygen_to": "oqs_mlkem"},
    "dry_run": false
  }
}
```

**Backend returns:**
```json
{
  "patch_id": "uuid",
  "patches": [
    {
      "file": "auth_service.py",
      "original_line": 284,
      "original_code": "key = RSA.generate(2048)",
      "patched_code": "kem = KeyEncapsulation('ML-KEM-768')",
      "rule": "PY-RSA-GEN-001→PQC-ML-KEM-768",
      "confidence": 0.91,
      "breaking_change": false,
      "test_required": true,
      "migration_notes": "Replace PKCS1_OAEP calls with kem.encap_secret / kem.decap_secret pattern"
    }
  ],
  "unified_diff": "--- a/auth_service.py\n+++ b/auth_service.py\n...",
  "test_script": "...",
  "caveats": ["ML-KEM requires oqs-python>=0.10.0", "pqcrypto package is an alternative"]
}
```

**What the patch engine MUST NOT do:**
- Use an LLM to generate arbitrary code changes
- Make changes it cannot verify via deterministic rule matching
- Patch production-deployed binaries
- Claim a patch is safe without running the generated tests

**UI:** Shows the unified diff with syntax highlighting. Download `.patch` file. Copy diff. "Run Tests" button triggers test execution in backend sandbox and shows results.

---

### 3.14 MIGRATION PLANNER

**Purpose:** Creates a structured migration workstream for transitioning discovered algorithms to PQC alternatives.

**Backend:** `POST /api/migration/plans?project={id}`
```json
{
  "scan_ids": ["uuid1", "uuid2"],
  "target_hosting": "on-prem",
  "data_sensitivity_years": 25,
  "migration_mode": "HYBRID_TRANSITION"
}
```

**Plan structure:**
```json
{
  "plan_id": "uuid",
  "created_at": "ISO",
  "phases": [
    {
      "phase": 1,
      "name": "Discovery & Evidence Locking",
      "status": "COMPLETED",
      "workstreams": ["Complete source scan", "Complete dependency audit", "Lock CBOM baseline"],
      "duration_estimate_weeks": "2-4",
      "estimate_basis": "heuristic"
    },
    {
      "phase": 2,
      "name": "Hybrid Key Exchange Staging",
      "status": "READY",
      "workstreams": ["Deploy ML-KEM hybrid alongside RSA", "Update TLS configurations", "Test backward compatibility"],
      "prerequisites": ["Phase 1 complete", "liboqs available in environment"],
      "duration_estimate_weeks": "4-8"
    },
    {
      "phase": 3,
      "name": "Closed-Loop Verification",
      "status": "BLOCKED",
      "workstreams": ["Re-scan all surfaces", "Compare evidence: RSA removed, ML-KEM present"],
      "blockers": ["Phase 2 must complete first"]
    },
    {
      "phase": 4,
      "name": "Classical Key Decommissioning",
      "status": "BLOCKED",
      "duration_estimate_weeks": "2-4"
    }
  ],
  "affected_assets": 8,
  "total_duration_estimate_weeks": "12-24",
  "disclaimer": "All duration estimates are ECDAT planning heuristics for one engineer. Not measured delivery commitments. Actual timelines depend on team size, environment complexity, and vendor dependencies.",
  "nist_reference": "https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc",
  "evidence_gaps": ["No firmware scan completed — firmware crypto assets unknown"],
  "missing_inputs": []
}
```

**UI:** Phase cards in a vertical stepper. Each phase shows its status badge, workstreams as a checklist (backend-driven, not frontend-hardcoded), dependencies, and duration. A "Gantt-style" horizontal timeline at the top shows phases overlaid.

---

### 3.15 VERIFICATION ENGINE

**Purpose:** Compare a baseline scan with a post-migration scan. Produce VERIFIED / NOT_VERIFIED / INCONCLUSIVE per asset.

**Backend:** `POST /api/verify/compare`
```json
{
  "baseline_scan_ids": ["uuid1"],
  "post_migration_scan_ids": ["uuid2"],
  "project_id": "string"
}
```

**Returns:**
```json
{
  "verification_id": "uuid",
  "verdict": "PARTIALLY_VERIFIED",
  "retired_assets": [
    {"algorithm": "MD5", "location": "auth.py:12", "status": "CONFIRMED_ABSENT", "evidence": "Re-scan found SHA-256 at same location"}
  ],
  "new_assets": [
    {"algorithm": "ML-KEM-768", "location": "auth.py:12", "status": "CONFIRMED_PRESENT"}
  ],
  "unchanged_vulnerable": [
    {"algorithm": "RSA-2048", "location": "legacy_api.py:88", "status": "STILL_PRESENT", "note": "Migration not yet applied to this file"}
  ],
  "regressions": [],
  "inconclusive": [],
  "summary": "3/5 vulnerable assets retired. 2 remain. No regressions introduced."
}
```

**UI:** Three columns side by side: "Removed (✓)", "Added (new)", "Unchanged/Remaining (!)". Each asset row has evidence link. Verdict badge at top (green=VERIFIED, red=NOT_VERIFIED, amber=PARTIALLY_VERIFIED, gray=INCONCLUSIVE). The evidence comparison table shows the exact before/after evidence records side by side.

---

### 3.16 STANDARDS & MANDATES

**Purpose:** Map discovered algorithms against regulatory compliance requirements.

**Backend:** `GET /api/standards/compliance?project={id}`

**Mapped standards:**
- NSA CNSA 2.0 (2022) — specifies PQC transition timelines
- NIST FIPS 203/204/205 — ML-KEM, ML-DSA, SLH-DSA
- NIST SP 800-131A — algorithm transitions
- BSI TR-02102 — German federal standards
- PCI-DSS 4.0 — payment card crypto requirements
- NIST IR 8547 — PQC migration guidance

**Each standard row:**
```json
{
  "standard": "NSA CNSA 2.0",
  "requirement": "Transition RSA/ECC key establishment to ML-KEM by 2030",
  "status": "NON_COMPLIANT",
  "affected_asset_count": 5,
  "deadline": "2030",
  "evidence": "5 RSA-2048 assets found; 0 ML-KEM assets found",
  "remediation": "Deploy ML-KEM-768 for key encapsulation"
}
```

**UI:** Table with standards as rows. Status: green=COMPLIANT, red=NON_COMPLIANT, amber=PARTIALLY_COMPLIANT, gray=INSUFFICIENT_EVIDENCE. Click row → drawer with full requirement text, affected assets, remediation steps.

**Important:** Standards data is from the knowledge base (versioned JSON files in `backend/knowledge/`), not LLM-generated. The compliance status is computed by comparing known-bad algorithm IDs against discovered asset algorithm IDs.

---

### 3.17 RUNTIME & eBPF

**Purpose:** Show live cryptographic calls from running processes (experimental — clearly labeled).

**Status:** This feature is experimental. If eBPF probes are not available in the current environment (no kernel support, no root, no container privileges), show clearly:

```
RUNTIME TRACING: UNAVAILABLE
Reason: eBPF probes require root/CAP_SYS_ADMIN and Linux kernel 5.8+.
Current environment: [detected OS/kernel here]
This feature is available when ECDAT backend runs with appropriate permissions on Linux.
[How to enable] [Documentation]
```

Do NOT show fake runtime data if the tracer is not running.

**When available:**
- `GET /api/runtime/status` → returns whether tracer is active
- `GET /api/runtime/calls?project={id}&since={timestamp}` → streaming SSE endpoint
- Frontend shows a live table of: PID, process_name, function, algorithm, key_size, timestamp
- Auto-refreshes via Server-Sent Events

---

### 3.18 BINARY ML & PCAP

**Binary ML:**
- Triggered when a binary scan job completes — results auto-populate this panel
- Shows: entropy heatmap (byte-level visualization), section analysis (ELF/PE sections with entropy per section), detected crypto signatures, ML confidence scores
- `GET /api/binary/{scan_id}/analysis` → returns entropy map data + classifier results
- **Entropy heatmap:** 256×N SVG grid where each cell color represents entropy of a 256-byte block (white=high/encrypted, dark=low/plaintext)

**PCAP:**
- Input: Upload `.pcap` or `.pcapng` file (max 100MB)
- `POST /api/scan/pcap`
- Backend uses scapy/dpkt to parse TLS handshakes, extract: cipher suite, TLS version, JA3 fingerprint, key exchange groups
- Returns evidence records with `evidence_type: "PCAP_TLS_HANDSHAKE"`, `evidence_level: "E3"`
- Clearly states: "PCAP analysis requires authorized packet captures from systems you own."
- Does not attempt to decrypt TLS content — only handshake metadata

---

### 3.19 CYCLONEDX CBOM

**Purpose:** Generate and download a machine-readable Cryptography Bill of Materials in CycloneDX 1.6 format.

**Backend:** `POST /api/export/cbom?project={id}`
```json
{
  "scan_ids": ["uuid1", "uuid2"],
  "target_name": "Payment Infrastructure v2.1",
  "include_evidence": true
}
```

**Returns:** A downloadable JSON file conforming to CycloneDX 1.6 CBOM schema. The backend already has `cbom_generator.py` — ensure it:
- Only includes assets from the selected scan IDs (not all project assets)
- Validates against the vendored schema JSON before returning
- Includes evidence provenance per component
- Does NOT include unmeasured security levels (per current V4 rule)

**UI:** Dropdown to select which scan jobs to include. Preview shows component count. Download button. Copy JSON button. Optional: render a human-readable HTML preview of the CBOM.

---

### 3.20 REPORT CENTER

**Purpose:** Generate downloadable security reports for different audiences.

**Report types:**

| Report | Audience | Content |
|--------|----------|---------|
| Executive Summary | CISO/Leadership | Risk posture score, critical findings count, top 3 actions, Mosca deadline |
| Technical Inventory | Security Engineers | Full asset table, evidence details, confidence scores |
| Quantum Risk Report | Security Architects | Shor/Grover breakdown, HNDL analysis, Mosca per-algorithm |
| Migration Roadmap | Project Managers | Phased plan, effort estimates, blockers |
| Verification Report | Auditors | Before/after evidence comparison, verification verdicts |
| Archive Security | Archive Owners | Archive encryption quality, recommendations |
| CycloneDX CBOM | Tools/Scanners | Machine-readable JSON |

**Backend:** `POST /api/reports/generate`
```json
{
  "report_type": "quantum_risk",
  "project_id": "string",
  "format": "pdf | html | json"
}
```

**Each report is generated server-side and returned as a download.** The frontend does not assemble the report from API calls — the backend renders it. This ensures reports are consistent and reproducible.

If no scans have been run: "No data to report. Complete at least one discovery scan."

---

### 3.21 SECURE ARCHIVE LAB

**Purpose:** Analyze encrypted archives and optionally create stronger protected vaults.

**Panel A — Analyze Archive:**
- Input: Upload archive (ZIP, 7z) + optional password
- Backend: `POST /api/scan/archive`
- Returns:
  - Archive format, encryption scheme on the archive itself (ZipCrypto / AES-128 / AES-256 / None)
  - Quantum vulnerability of the archive encryption
  - If password provided + AES: content is decrypted in memory and inner files scanned for crypto
  - If no password: "Content encrypted — cannot inspect without password. Metadata analysis only."
  - Never attempt to crack passwords. Never store passwords.

**Panel B — Create Protected Vault (.ecvault):**
- Input: Files to protect, protection mode selection
- Protection modes:
  1. **Password Vault**: User provides password → Argon2id KDF → AES-256-GCM encryption
  2. **Recipient-Key Vault**: Upload recipient's ML-KEM-768 public key → encrypt data key with ML-KEM
  3. **Hybrid Vault**: AES-256-GCM payload + X25519/ML-KEM-768 hybrid key encapsulation
- Backend: `POST /api/archive/create-vault`
- Returns: `.ecvault` file download + manifest JSON
- Manifest shows: algorithms, parameters, assumptions, protection model, version — NO secrets
- System NEVER claims "unbreakable" — shows: "AES-256-GCM with Argon2id. 128-bit quantum security (Grover). Key establishment: ML-KEM-768 (FIPS 203)."

**Panel C — Verify Vault:**
- Input: Upload `.ecvault` + key material
- Backend verifies: integrity hash, decryptability, manifest consistency
- Returns: VERIFIED / FAILED / INCONCLUSIVE with specific failure reason

---

## PART 4 — AI COPILOT BUTTON

The "AI Copilot" button in the top navigation bar currently exists in the UI. Implement it as:

**What it does:** Uses Gemini API (already integrated as `gemini_assistant.py`) to explain findings in plain English.

**Input:** Whatever the user is currently looking at (current panel + selected asset IDs)

**Context sent to Gemini:**
```json
{
  "current_panel": "quantum_risk",
  "selected_assets": [...],
  "question": "user's question if they typed one, else null"
}
```

**Gemini is used ONLY for explanation, NOT for:**
- Generating cryptographic recommendations (that comes from the knowledge base)
- Inventing algorithm properties
- Predicting specific dates

The copilot says "Based on ECDAT evidence, RSA-2048 was found in auth_service.py. Here's what that means for your quantum risk..." — not "I think your system might use X."

---

## PART 5 — NETWORK SCANNER COMPLETE REWRITE

This is the most critical fix. The current scanner returns fake/random confidence values and infers cipher support it never tested.

**File to rewrite:** `backend/engine/network_prober.py`

**Absolute rules:**
1. Only report what was actually negotiated in a real handshake
2. If a cipher was not tested, its status is `NOT_TESTED` — never `UNSUPPORTED` or `SUPPORTED`
3. Confidence values are derived from evidence quality (E3 = dynamic probe = high confidence for what WAS observed), not random floats
4. Timeout → property is `UNKNOWN`, not guessed
5. Never test more than 20 cipher candidates (bounded budget)

**What the scanner actually does:**

```python
# backend/engine/network_prober.py — REWRITE

import ssl, socket, asyncio, time
from dataclasses import dataclass
from typing import Optional

@dataclass
class TLSProbeResult:
    """Result of a single TLS probe attempt. Only carries what was directly observed."""
    hostname: str
    port: int
    
    # What we actually negotiated (None = not tested or failed)
    negotiated_protocol: Optional[str]    # "TLSv1.3", "TLSv1.2", etc.
    negotiated_cipher: Optional[str]      # The actual negotiated cipher name
    negotiated_kex: Optional[str]         # Key exchange group
    
    # Certificate (only from actually observed cert chain)
    cert_subject: Optional[str]
    cert_issuer: Optional[str]
    cert_not_after: Optional[str]
    cert_key_algorithm: Optional[str]     # "RSA" | "EC" | "ED25519" | etc.
    cert_key_size: Optional[int]
    cert_signature_hash: Optional[str]
    
    # Protocol version probes (only: ACCEPTED | REJECTED | TIMEOUT | NOT_TESTED)
    tls10_status: str = "NOT_TESTED"
    tls11_status: str = "NOT_TESTED"
    tls12_status: str = "NOT_TESTED"
    tls13_status: str = "NOT_TESTED"
    
    # PQC hybrid probes (only: NEGOTIATED | REJECTED | UNAVAILABLE_ON_SCANNER | INCONCLUSIVE | NOT_TESTED)
    pqc_x25519mlkem768: str = "NOT_TESTED"
    pqc_secp256r1mlkem768: str = "NOT_TESTED"
    pqc_secp384r1mlkem1024: str = "NOT_TESTED"
    
    # HTTP headers (only what was actually received)
    hsts_present: Optional[bool] = None
    hsts_max_age: Optional[int] = None
    
    # Errors
    connection_error: Optional[str] = None
    
    # Evidence metadata
    evidence_level: str = "E3"   # Dynamic probe — high for what WAS observed
    probe_timestamp: str = ""
    probe_duration_ms: int = 0

async def probe_tls_endpoint(hostname: str, port: int = 443) -> TLSProbeResult:
    """
    Perform actual TLS probes. Return only what was observed.
    Never infer or guess.
    """
    result = TLSProbeResult(hostname=hostname, port=port)
    start = time.perf_counter()
    
    # Resolve hostname once (pin to one IP for all probes)
    try:
        infos = await asyncio.wait_for(
            asyncio.get_event_loop().run_in_executor(None, socket.getaddrinfo, hostname, port, 0, socket.SOCK_STREAM),
            timeout=3.0
        )
        if not infos:
            result.connection_error = "DNS resolution returned no results"
            return result
        target_ip = infos[0][4][0]
    except asyncio.TimeoutError:
        result.connection_error = "DNS timeout"
        return result
    except Exception as e:
        result.connection_error = f"DNS error: {str(e)[:100]}"
        return result
    
    # Main connection — get negotiated cipher, cert, protocol
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        
        conn = await asyncio.wait_for(
            _do_connect(hostname, target_ip, port, ctx),
            timeout=5.0
        )
        if conn:
            result.negotiated_protocol = conn.get("protocol")
            result.negotiated_cipher = conn.get("cipher_name")
            result.negotiated_kex = conn.get("kex_group")
            cert = conn.get("cert", {})
            result.cert_subject = cert.get("subject")
            result.cert_issuer = cert.get("issuer")
            result.cert_not_after = cert.get("not_after")
            result.cert_key_algorithm = cert.get("key_algorithm")
            result.cert_key_size = cert.get("key_size")
            result.cert_signature_hash = cert.get("signature_hash")
    except asyncio.TimeoutError:
        result.connection_error = "TLS handshake timeout (5s)"
    except ssl.SSLError as e:
        result.connection_error = f"TLS error: {str(e)[:100]}"
    
    # Protocol version probes (test TLS 1.0, 1.1 — should be rejected)
    for version_name, version_const in [
        ("tls10", ssl.TLSVersion.TLSv1),
        ("tls11", ssl.TLSVersion.TLSv1_1),
        ("tls12", ssl.TLSVersion.TLSv1_2),
        ("tls13", ssl.TLSVersion.TLSv1_3),
    ]:
        try:
            probe_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            probe_ctx.check_hostname = False
            probe_ctx.verify_mode = ssl.CERT_NONE
            probe_ctx.minimum_version = version_const
            probe_ctx.maximum_version = version_const
            await asyncio.wait_for(_do_connect(hostname, target_ip, port, probe_ctx), timeout=4.0)
            setattr(result, f"{version_name}_status", "ACCEPTED")
        except asyncio.TimeoutError:
            setattr(result, f"{version_name}_status", "TIMEOUT")
        except ssl.SSLError:
            setattr(result, f"{version_name}_status", "REJECTED")
        except Exception:
            setattr(result, f"{version_name}_status", "INCONCLUSIVE")
    
    # PQC hybrid probes using OpenSSL 3.5+
    # If local OpenSSL does not support PQC groups, return UNAVAILABLE_ON_SCANNER — not server non-support
    for group_name, attr in [
        ("x25519_mlkem_768", "pqc_x25519mlkem768"),
        ("secp256r1_mlkem_768", "pqc_secp256r1mlkem768"),
        ("secp384r1_mlkem_1024", "pqc_secp384r1mlkem1024"),
    ]:
        probe_result = await _probe_pqc_group(hostname, target_ip, port, group_name)
        setattr(result, attr, probe_result)
    
    result.probe_duration_ms = int((time.perf_counter() - start) * 1000)
    result.probe_timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    return result
```

**Convert TLSProbeResult to EvidenceRecords:**
Each probe result becomes one or more evidence records with `evidence_type = "TLS_NEGOTIATION"`, `evidence_level = "E3"`, and `observed_value` containing only what was actually seen. The confidence for E3 evidence is 0.90 by default (not random).

---

## PART 6 — COMPLETE API CONTRACT

All endpoints. Backend must implement all of these. Frontend must call only these — never construct fake responses.

```
AUTH
POST   /api/auth/register          body: {email, password, name}
POST   /api/auth/login             body: {email, password} → {token}
POST   /api/auth/logout
GET    /api/auth/me                → {user_id, email, name, role}

PROJECTS
GET    /api/projects               → [{id, name, env, criticality, created_at}]
POST   /api/projects               body: {name, environment, criticality, data_sensitivity_years, description}
GET    /api/projects/{id}          → full project detail
PUT    /api/projects/{id}          body: partial project update
DELETE /api/projects/{id}

SCANS
POST   /api/scan/sources           body: multipart file(s) | {source_text, filename, language}
POST   /api/scan/github            body: {repo_url, token?, branch?, subdir?, project_id}
POST   /api/scan/binary            body: multipart binary file
POST   /api/scan/network           body: {hostname, port?, project_id, authorized: true}
POST   /api/scan/certificate       body: multipart PEM | {pem_text} | {hostname_for_live_cert}
POST   /api/scan/archive           body: multipart archive + optional {password}
POST   /api/scan/dependencies      body: multipart manifest file(s)
POST   /api/scan/pcap              body: multipart .pcap file
GET    /api/scans?project=&limit=&offset=
GET    /api/scans/{id}             → scan job detail
POST   /api/scans/{id}/cancel
GET    /api/scans/{id}/evidence    → evidence records for this scan

CHUNKED UPLOAD
POST   /api/upload/chunk           headers: X-Upload-ID, X-Chunk-Index, X-Total-Chunks, X-Filename, X-Surface
GET    /api/upload/{upload_id}/status

ASSETS
GET    /api/assets?project=&filter[*]=&sort=&page=&per_page=
GET    /api/assets/{id}
GET    /api/assets/{id}/evidence
GET    /api/assets/{id}/blast-radius
GET    /api/assets/{id}/relationships

QUANTUM
GET    /api/quantum/risk-summary?project=
POST   /api/quantum/estimate-shor  body: {algorithm, key_size_bits, physical_error_rate, surface_code_distance}
POST   /api/quantum/grover-analysis body: {algorithm, key_size_bits}
POST   /api/quantum/mosca          body: {algorithm, key_size, data_sensitivity_years, migration_time_years}
POST   /api/quantum/mosca-project-scan body: {project_id, data_sensitivity_years?}
GET    /api/quantum/timeline-summary?project=
POST   /api/quantum/shor-demo      → {keypair, encrypted_message, factoring_result, resource_estimates}

GRAPH
GET    /api/graph?project=         → {nodes, edges}

MIGRATION
POST   /api/migration/plans?project=
GET    /api/migration/plans?project=
GET    /api/migration/plans/{id}

AGILITY
GET    /api/agility/assessment?project=

STANDARDS
GET    /api/standards/compliance?project=

PATCH
POST   /api/patch/generate         body: {scan_id, asset_ids, patch_options}
GET    /api/patch/{patch_id}

VERIFICATION
POST   /api/verify/compare         body: {baseline_scan_ids, post_migration_scan_ids, project_id}
GET    /api/verify/{verification_id}

EXPORT
POST   /api/export/cbom?project=   body: {scan_ids, target_name, include_evidence}
POST   /api/reports/generate       body: {report_type, project_id, format}

ARCHIVE
POST   /api/archive/create-vault   body: multipart files + {mode, password?, recipient_pubkey?}
POST   /api/archive/verify-vault   body: multipart .ecvault + key material
GET    /api/archive/vault/{id}

CUSTOM LOOP
POST   /api/custom-loop/run        body: {project_id, target_type, target, loop_options}
GET    /api/custom-loop/{run_id}/status
GET    /api/custom-loop/{run_id}/results

RUNTIME
GET    /api/runtime/status
GET    /api/runtime/calls?project=&since=  (SSE)

OVERVIEW
GET    /api/overview?project=
GET    /api/health

KNOWLEDGE BASE
GET    /api/knowledge/algorithms   → versioned algorithm knowledge base
GET    /api/knowledge/version      → {rules_version, hash, published_at}
```

---

## PART 7 — DATABASE SCHEMA (SQLite, WAL mode)

```sql
-- Projects
CREATE TABLE projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  environment TEXT DEFAULT 'development',
  criticality TEXT DEFAULT 'medium',
  data_sensitivity_years INTEGER DEFAULT 10,
  description TEXT,
  is_demo INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- Scan Jobs
CREATE TABLE scan_jobs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  surface TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  input_hash TEXT,
  input_summary TEXT,
  scanner_version TEXT,
  rules_version TEXT,
  started_at TEXT,
  completed_at TEXT,
  error_detail TEXT,
  created_at TEXT NOT NULL
);

-- Crypto Assets
CREATE TABLE crypto_assets (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  scan_id TEXT REFERENCES scan_jobs(id),
  algorithm TEXT NOT NULL,
  key_size INTEGER,
  role TEXT,
  surface TEXT NOT NULL,
  location TEXT,
  evidence_level TEXT NOT NULL DEFAULT 'E1',
  confidence REAL NOT NULL DEFAULT 0.5,
  quantum_risk TEXT DEFAULT 'UNKNOWN',
  mosca_score REAL,
  mosca_verdict TEXT,
  pqc_replacement TEXT,
  discovered_at TEXT NOT NULL
);

-- Evidence Records
CREATE TABLE evidence_records (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  asset_id TEXT REFERENCES crypto_assets(id),
  scan_id TEXT NOT NULL REFERENCES scan_jobs(id),
  surface TEXT NOT NULL,
  evidence_type TEXT NOT NULL,
  evidence_level TEXT NOT NULL,
  algorithm TEXT NOT NULL,
  cryptographic_role TEXT,
  location TEXT,
  line_number INTEGER,
  byte_offset INTEGER,
  snippet TEXT,
  rule_id TEXT,
  rule_version TEXT,
  scanner_version TEXT,
  input_hash TEXT,
  confidence REAL NOT NULL,
  observed_value TEXT,
  timestamp TEXT NOT NULL
);

-- Asset Graph
CREATE TABLE graph_nodes (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  asset_id TEXT REFERENCES crypto_assets(id),
  node_type TEXT NOT NULL,
  label TEXT NOT NULL,
  properties TEXT  -- JSON
);

CREATE TABLE graph_edges (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  source_node_id TEXT NOT NULL REFERENCES graph_nodes(id),
  target_node_id TEXT NOT NULL REFERENCES graph_nodes(id),
  relationship TEXT NOT NULL,
  confidence REAL,
  evidence_id TEXT REFERENCES evidence_records(id)
);

-- Migration Plans
CREATE TABLE migration_plans (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  scan_ids TEXT NOT NULL,  -- JSON array
  phases TEXT NOT NULL,    -- JSON
  created_at TEXT NOT NULL
);

-- Verification Results
CREATE TABLE verification_results (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  baseline_scan_ids TEXT NOT NULL,   -- JSON array
  post_scan_ids TEXT NOT NULL,       -- JSON array
  verdict TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Custom Loop Runs
CREATE TABLE loop_runs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL REFERENCES projects(id),
  target_type TEXT NOT NULL,
  target TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'running',
  steps_json TEXT,
  results_json TEXT,
  created_at TEXT NOT NULL,
  completed_at TEXT
);

-- Upload Chunks (for large file assembly)
CREATE TABLE upload_sessions (
  upload_id TEXT PRIMARY KEY,
  filename TEXT NOT NULL,
  surface TEXT NOT NULL,
  total_chunks INTEGER NOT NULL,
  received_chunks INTEGER DEFAULT 0,
  temp_path TEXT,
  status TEXT DEFAULT 'receiving',
  created_at TEXT NOT NULL
);
```

---

## PART 8 — IMPLEMENTATION PRIORITY ORDER

Work in this exact order. Do not jump ahead.

### Phase 1 — Data Integrity (must be done first, everything depends on it)
1. Implement real authentication (JWT tokens, protected routes)
2. Implement Projects CRUD with isolation (each project has its own asset/evidence namespace)
3. Implement empty state system (zero fake/demo data outside the demo project)
4. Fix graph integrity (graph nodes created only from real assets, edges only between existing nodes)
5. Fix overview endpoint to aggregate from real DB records

### Phase 2 — Core Scanners Working End-to-End
6. Rewrite network_prober.py (see Part 5 — highest priority fix)
7. Wire source scanner to return evidence records to DB (not just return JSON)
8. Implement scan job status polling (queued → running → completed)
9. Implement asset inventory with real DB query + filters
10. Implement evidence explorer with real DB query

### Phase 3 — New Input Surfaces
11. Implement GitHub scanner (github_scanner.py)
12. Implement chunked upload for large files
13. Implement archive scanner with ZIP encryption type detection
14. Implement dependency manifest scanner

### Phase 4 — Quantum Analysis Layer
15. Implement Mosca engine (mosca.py) — wire to all asset records
16. Implement Grover analysis endpoint
17. Implement Shor's resource estimator (interactive)
18. Implement Shor's live demo (RSA-512 factoring)
19. Implement quantum timeline summary for dashboard

### Phase 5 — Graph & Risk
20. Implement real crypto asset graph from DB evidence
21. Implement blast radius BFS traversal
22. Implement crypto agility assessment
23. Implement standards compliance mapping

### Phase 6 — Migration & Output
24. Implement migration planner with phase generation
25. Implement verification engine (before/after compare)
26. Implement CBOM export (existing, validate it works with real data)
27. Implement report generation (at least Executive + Quantum Risk + CBOM)

### Phase 7 — Advanced Features
28. Implement custom loop end-to-end
29. Implement secure archive lab (analyze + create vault)
30. Implement patch engine (deterministic rules only)
31. Wire AI Copilot to Gemini API with real context

---

## PART 9 — UI REQUIREMENTS & FIXES

### What to keep from the current UI:
- The sidebar structure (all section labels are correct)
- The obsidian dark theme (#0a0a0f background approximately)
- The header with project selector, Command Menu, AI Copilot, refresh, dark mode toggle
- The badge system (PRODUCTION, CRITICAL, etc.)
- The evidence-level color system

### What must be fixed:

**Fix 1: No static text anywhere that mentions demo/example data on real projects**
The subtitle "Controlled demonstration project showcasing post-quantum discovery..." must only appear when `project.is_demo === true`.

**Fix 2: Metric cards must not show static numbers**
Every number in the 5 metric cards (Crypto Assets: 16, Quantum-Relevant: 5, etc.) must come from `GET /api/overview?project={id}`. Show a skeleton loader while fetching, then render real numbers.

**Fix 3: Sidebar badges must reflect real counts**
The "(18)" next to Scan Jobs and "(16)" next to Asset Inventory must be real counts from the DB.

**Fix 4: Empty states must be helpful and specific**
Every panel that has no data must show:
```
[Icon]
[Panel Name]: No data yet
[One sentence explaining why it's empty]
[Action button that takes them to where they need to go]
```

**Fix 5: All charts must be conditional on data existence**
Never render a donut chart with 0 total assets. Never render a bar chart with an empty array. Show the empty state instead.

**Fix 6: Scan Studio form must actually submit to backend**
Currently the scan form may not properly wire to all backend surfaces. Ensure all 8 surface types submit to their respective API endpoints and create scan jobs in the DB.

**Fix 7: Crypto Graph must not show edges without nodes**
Remove any graph seeding code. Graph is built purely from `GET /api/graph?project={id}`.

### Modern UI enhancements (add on top of fixes):
- Add a "Posture Score" circular gauge on the Executive Overview (0-100, computed server-side from asset risk distribution)
- Add sparkline charts for "asset count over time" and "scan activity" in the dashboard
- Add inline evidence level badges everywhere an evidence_level field is shown (E0 gray, E1 yellow, E2 cyan, E3 green, E4 blue, E5 purple)
- Add confidence bars on every asset row (thin horizontal bar, 0-100%)
- Add a top banner when a scan is running: "Scan in progress — [surface] — [job ID] — [elapsed time]"
- Add keyboard shortcuts: `N` = new scan, `⌘K` = command menu, `G` = go to graph

---

## PART 10 — WHAT THIS PROJECT MUST NEVER DO

1. Show a confidence value that was not computed from evidence quality
2. Report a cipher suite as SUPPORTED or UNSUPPORTED without testing it
3. Show graph edges without corresponding graph nodes
4. Show migration recommendations for assets that don't exist yet
5. Use an LLM to generate cryptographic replacement recommendations
6. Execute uploaded binary or source files
7. Store user passwords, API tokens, or private keys in the database (hashed passwords only; tokens in session only)
8. Allow scans of private IPs without explicit ECDAT_ALLOWED_CIDRS configuration
9. Claim VERIFIED without actual evidence comparison showing the change
10. Show any number in the dashboard that came from a hardcoded constant

---

*ECDAT — Evidence-Driven Cryptographic Discovery & Post-Quantum Migration Platform*
*SIH 2026 | NTRO PS-26164 | Evidence > Assumption | Observed ≠ Inferred*
