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
- **TLS:** DNS is capped at 3 seconds; connections are pinned to a checked resolved address. Collects a negotiated connection and certificate, separately checks trust/hostname, probes four protocol versions and four TLS 1.2 cipher candidates within a bounded budget. This is not exhaustive cipher enumeration. Unsupported local OpenSSL algorithms remain unnegotiated, never inferred as supported. Negotiated groups/PQC, revocation and full certificate-chain inventory are not measured.
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
