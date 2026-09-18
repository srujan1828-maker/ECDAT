# ECDAT — cryptographic discovery with evidence

ECDAT scans source files, TLS endpoints, and binary/firmware uploads. Version 3 removes automatic demo fallbacks and seeded dashboard findings. A failed scan stays failed, and an unmeasured property stays unknown.

## Run locally

```sh
docker compose up --build
```

Open http://localhost:3000. Compose binds both services to localhost, proxies browser API calls through Next.js, and persists scan history in the `scan-data` volume. Docker is optional: install `backend/requirements.txt`, run `python backend/main.py` from the repository root, then run `npm ci` and `npm run dev` inside `frontend`.

For the Python command, the default SQLite path is relative to the process working directory. Set `ECDAT_DB` to an absolute path for deployment.

## Scan workflow

1. Open a project name. Projects partition records, but are not separate user authorization boundaries.
2. Enter an authorized TLS hostname/URL, paste source, select multiple source files/a folder, or upload a binary/ZIP.
3. Start the scan. Jobs return an ID immediately and progress through queued, running, completed, failed, or cancelled.
4. Inspect findings, coverage, errors, input hashes, and measured details. A completed job can have partial source coverage; zero matches is not proof of safety.
5. Select completed scans in history and export their CycloneDX 1.6 CBOM. Exports use stored records, not client-supplied findings.

No input is synthesized. No source files or uploaded binaries are executed. Original uploads are held in memory only while queued/running; stored records contain input hashes and results, which can include source snippets. Binary previews are omitted to avoid returning private-key bytes. Protect the database accordingly.

## Capabilities and limits

- **Source:** Python AST analysis, common import aliases, literal constants, and simple cross-file module constants. Other supported languages (Java, C/C++, Go, JavaScript/TypeScript) use comment-aware regex rules, including multiline calls. Coverage labels these as heuristic. `package.json` and `requirements.txt` provide dependency inventories, not dependency vulnerability analysis. No general interprocedural analysis, full language parsers outside Python, or remote repository cloning yet.
- **Binary:** Real byte uploads, ELF/PE section attribution, repeated AES/DES/hash signatures and reversed word byte orders, file hashes, and entropy coverage across the entire file. ZIP expansion is bounded to one level, 100 entries and 8 MiB total. Nested/other archive formats are not unpacked. A constant match does not establish active use or key size; entropy does not establish encryption.
- **TLS:** DNS is capped at 3 seconds; connections are pinned to a checked resolved address. Collects a negotiated connection and certificate, separately checks trust/hostname, probes four protocol versions and four TLS 1.2 cipher candidates within a bounded budget. This is not exhaustive cipher enumeration. Unsupported local OpenSSL algorithms remain unnegotiated, never inferred as supported. Separate TLS 1.3 handshakes test X25519MLKEM768, SecP256r1MLKEM768 and SecP384r1MLKEM1024, with X25519 as a classical control. Each group reports negotiation, rejection, unavailable scanner support or inconclusive evidence. These probes measure server capability, not the default connection or PQ-safe certificate signatures. Revocation and full certificate-chain inventory are not measured.
- **Jobs:** SQLite records survive restart. Two worker threads and at most 20 active/queued jobs. Pending/running jobs become failed on restart and can be resubmitted. Cancellation suppresses result collection; it does not forcibly kill an already running operation. Use exactly **one API process/replica** for this implementation. Multi-process worker coordination and automatic retries are not implemented.
- **History:** UI/API show the newest 200 jobs per project. Exports accept up to 200 selected completed scan IDs. There is no retention/deletion policy yet.
- **CBOM:** Conservative asset mappings and per-finding provenance. Unmeasured security levels are omitted. Official CycloneDX 1.6 schema validation runs in tests.

## Configuration

| Variable | Service | Meaning |
|---|---|---|
| `BACKEND_API_URL` | Next.js | Runtime backend URL, including `/api`. Local default: `http://127.0.0.1:8000/api`; Compose uses `http://backend:8000/api`. |
| `ECDAT_DB` | Backend | Persistent SQLite path; Compose uses `/data/scans.sqlite3`. |
| `ECDAT_API_TOKEN` | Backend | Optional shared bearer token. Set it for any deployment beyond localhost; enter it in the dashboard's token field. Never use a `NEXT_PUBLIC_` variable for this secret. |
| `ECDAT_ALLOWED_CIDRS` | Backend | Explicit private/local network allowlist, e.g. `192.168.1.0/24`. Default denies non-public target addresses. |
| `CORS_ORIGINS` | Backend | Exact comma-separated origins for direct browser clients. No permissive regex is applied. Same-origin proxy clients do not need cross-origin access. |
| `PORT`, `HOST` | Backend | Listen settings. Docker honors `PORT` and binds `0.0.0.0`; Python launcher defaults to localhost. |

For remote deployment, configure `BACKEND_API_URL` on the frontend service at runtime, attach persistent storage to the backend, and use a token and TLS. The Next.js proxy forwards the user's bearer token; it does not inject credentials for unauthenticated visitors. Authentication is shared-token access, not multi-tenant user accounts. The old `NEXT_PUBLIC_API_URL` is no longer used.

## API changes in v3

`POST /api/scan/network`, `/api/scan/code`, `/api/scan/sources`, `/api/scan/binary`, and `/api/scan/binary/upload` return **202 plus a scan record**, not synchronous findings. Poll `GET /api/scans/{id}?project=...`; list with `GET /api/scans?project=...`. Cancel with `POST /api/scans/{id}/cancel?project=...`.

`POST /api/export/cbom?project=...` accepts `{"scan_ids":["..."],"target_name":"..."}`. `/api/overview` summarizes persisted scans. `/api/health` is a lightweight health endpoint. Demo routes are removed. Root aliases remain for compatibility, but clients must adopt the asynchronous response contract.

## ECDAT V4 Core Foundation Architecture

ECDAT V4 introduces a research-grade, evidence-driven foundation separating raw observations from post-quantum risk, crypto-agility assessment, and blast radius calculation:

- **Evidence Model ($E_0..E_5$)**: Strict separation of confidence score ($[0.0, 1.0]$) from epistemological evidence tier ($E_0$ Metadata $\to$ $E_1$ Heuristic $\to$ $E_2$ Syntactic AST $\to$ $E_3$ Dynamic Probe $\to$ $E_4$ Corroborated $\to$ $E_5$ Hardware Attested). See [`docs/EVIDENCE_MODEL.md`](docs/EVIDENCE_MODEL.md).
- **ScanManifest & Reproducibility**: Bit-for-bit canonical JSON hashing, host environment capture (OS, kernel, Python, OpenSSL, CPU), and automated secret redaction. See [`docs/REPRODUCIBILITY.md`](docs/REPRODUCIBILITY.md).
- **Relational Asset Graph & Blast Radius**: Relational SQLite schema (`crypto_assets`, `evidence`, `graph_edges`) with foreign-key integrity, WAL mode, and reverse-dependency BFS traversal to compute affected upstream services. See [`docs/ASSET_GRAPH.md`](docs/ASSET_GRAPH.md).
- **Multi-Modal Evidence Fusion**: Reconciles findings across source code, binary disassemblies, and active TLS probes with probabilistic confidence fusion ($1 - \prod (1 - c_i)$), discrepancy tracking, and explainability. See [`docs/EVIDENCE_FUSION.md`](docs/EVIDENCE_FUSION.md).
- **Execution Sandbox**: Bounded execution isolation (`run_isolated`), timeout enforcement, memory bounds, and stdout/stderr volume limits. See [`docs/SANDBOX.md`](docs/SANDBOX.md).

### New V4 REST Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/scans/{id}/manifest` | `GET` | Retrieve the cryptographic reproducibility manifest and canonical hash. |
| `/api/scans/{id}/evidence` | `GET` | Retrieve raw and normalized evidence items associated with a scan. |
| `/api/scans/{id}/graph` | `GET` | Retrieve the cryptographic asset graph for a specific scan. |
| `/api/assets` | `GET` | Query discovered cryptographic assets partitioned by project. |
| `/api/assets/{id}` | `GET` | Retrieve single asset details, parameters, and PQC vulnerability status. |
| `/api/assets/{id}/evidence` | `GET` | Fetch all linked evidence items supporting the discovery of this asset. |
| `/api/assets/{id}/relationships` | `GET` | Retrieve incoming and outgoing relational edges for an asset. |
| `/api/assets/{id}/blast-radius` | `GET` | Calculate reverse blast radius, upstream caller dependencies, and risk amplification. |
| `/api/graph` | `GET` | Global relational asset graph with node/edge traversal for visualization. |


## Verification

```sh
python -m pip install -r backend/requirements.txt -r backend/requirements-dev.txt
python -m pytest backend/tests -q
cd frontend
npm ci
npm run build
cd ..
python scripts/check_stack.py
```

Backend tests cover actual loopback TLS handshakes against an expired self-signed certificate, job-to-export workflows, Python aliases/constants, all supported language rule paths, actual binary uploads, ELF/PE sections, ZIP limits, cancellation, persistence, authentication, CORS, project partitioning, and CBOM schema validation. External network targets and provider deployments are not exercised by these tests.

The vendored `backend/tests/bom-1.6.schema.json` comes from https://github.com/CycloneDX/specification/blob/1.6/schema/bom-1.6.schema.json and retains its upstream license metadata.

## Discovery dashboard and migration planner

The root page introduces the platform; **Open dashboard** goes to `/dashboard`. The workspace includes a command center with real scan charts, starting tips, all three existing scan workflows, reports, and a migration planner. Dark/light mode applies throughout and remembers the browser preference. Deep links `/dashboard#network`, `#code`, `#binary`, and `#migration` open the corresponding workflow.

Network scans make one HTTPS `HEAD /` request and one bounded `GET /` HTML sample to the exact IP vetted during TLS collection. Headers are capped at 16 KiB with a three-second read deadline. Redirects are recorded but never followed. Only a small header allowlist is retained; cookies are not saved. An HTTP failure leaves successful TLS evidence intact. Cloudflare/Vercel/CloudFront header hints are explicitly inferred: they can be spoofed and do not prove the origin provider, physical region, deployment method, or traffic volume. The HTML sample is capped at 128 KiB and three seconds; scripts and subresources are never executed or fetched. Framework markers and linked dependency manifests provide labeled environment clues. Old scans remain usable; rescan to collect new evidence.

To create a plan:

1. Complete one website/network scan, then open **Migration planner**.
2. Select that scan and any source/binary scans you confirm belong to the website.
3. Review automatically discovered hosting/CDN and stack clues. Linked manifests can suggest database drivers. Optional corrections, target hosting, data size and transfer throughput are available in the collapsed environment section.
4. If available, enter analytics request/bandwidth totals and a dated observation period. Daily averages use inclusive calendar days; request totals are not unique visitors or peak load. No traffic is fabricated when these inputs are missing.
5. Build and review the saved draft. It includes hosting and cryptographic workstreams, evidence-linked priorities, missing inputs, validation and rollback steps. Download the full JSON or reopen a saved plan.

`POST /api/migration/plans?project=...` accepts the fields above and `scan_ids` (exactly one completed network scan, with optional completed source/binary scans from the same project). It returns **201** with a saved plan. `GET /api/migration/plans` lists the latest 100 plan summaries, and `GET /api/migration/plans/{id}` retrieves one. Shared-token access and project partitioning work as for scans. Plans are stored in the existing SQLite database and survive restarts.

Effort ranges are transparent ECDAT planning heuristics for one engineer, **not measured delivery dates**. The response exports the formula and assumptions. Transfer time is a theoretical minimum from supplied decimal GB and Mbps. Downtime is unknown until rehearsed. No infrastructure changes, credential collection, production migration, or claim of PQC readiness is performed. The old `/migration/simulate` endpoint remains for compatibility; the new UI uses `/migration/plans`.

The migration guidance links to [NIST NCCoE's migration project](https://www.nccoe.nist.gov/applied-cryptography/migration-to-pqc). Traffic inputs can come from owner-controlled logs or services such as [Cloudflare zone analytics](https://developers.cloudflare.com/analytics/account-and-zone-analytics/zone-analytics/).

### Design handoff

[Figma — ECDAT Discovery & Migration](https://www.figma.com/design/OakWmlX58LfFxdPff7UV46) contains editable Dark/Light foundations, Geist typography, reusable button/card variants, and the landing navigation/hero. Separate theme collections accommodate the Starter plan's one-mode limit. **Figma's MCP quota was exhausted before the remaining screen designs and final visual review could be completed.** The dashboard and migration frames in that file are unfinished; the full UI is implemented in this repository.

New UI modules live in `frontend/src/components/ecdat`; shared theme/layout styles are in `frontend/src/app/globals.css`. The scan workflow remains in `frontend/src/app/dashboard/page.tsx`. Validation covers TypeScript, the production frontend build, and the authenticated production proxy-to-backend workflow. Browser visual/interactivity review remains a follow-up because the available browser cannot access the local application in this environment.

### Post-quantum measurement runtime

Rebuild and redeploy the backend Docker image, then run a fresh network scan. The image uses Debian Trixie with OpenSSL 3.5 and checks hybrid group availability during build. An older local OpenSSL reports scanner upgrade required, never server non-support. `ECDAT_OPENSSL_BIN` can select another compatible executable. CI runs real local TLS servers for all three hybrid groups in the production image.

Migration plans distinguish ML-KEM key establishment from ML-DSA/SLH-DSA signatures, retain suitable symmetric cryptography, and include role-specific verification steps. Public certificate migration requires compatible clients, CA and infrastructure; a successful hybrid handshake alone does not establish full PQ readiness. Public discovery cannot prove hidden origin topology, deployment method or average traffic; these remain explicit gaps unless supplied by the owner.
