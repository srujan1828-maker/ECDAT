# ECDAT Website Architecture, System Operation & Component Guide

## Table of Contents
1. [Executive Summary & Platform Purpose](#1-executive-summary--platform-purpose)
2. [High-Level Architecture & Tech Stack](#2-high-level-architecture--tech-stack)
3. [Request Lifecycle & End-to-End Data Flow](#3-request-lifecycle--end-to-end-data-flow)
4. [Frontend Application Shell & Routing](#4-frontend-application-shell--routing)
5. [Domain-Specific Dashboard Components (`frontend/src/components/ecdat/`)](#5-domain-specific-dashboard-components)
   - [Overview Panel (`overview.tsx`)](#51-overview-panel-overviewtsx)
   - [Surface-Specific Scan History (`feature-scan-history.tsx`)](#52-surface-specific-scan-history-feature-scan-historytsx)
   - [Unified Evidence Viewer (`evidence-panels.tsx`)](#53-unified-evidence-viewer-evidence-panelstsx)
   - [Migration Planner (`migration-planner.tsx`)](#54-migration-planner-migration-plannertsx)
   - [Closed-Loop Verification Panel (`verification-panel.tsx`)](#55-closed-loop-verification-panel-verification-paneltsx)
   - [Cryptographic Standards Panel (`standards-panel.tsx`)](#56-cryptographic-standards-panel-standards-paneltsx)
   - [Experimental Innovations Hub (`experimental-hub.tsx`)](#57-experimental-innovations-hub-experimental-hubtsx)
   - [SIH 10-Step Interactive Demo (`sih-demo-panel.tsx`)](#58-sih-10-step-interactive-demo-sih-demo-paneltsx)
   - [Theme Switcher (`theme-toggle.tsx`)](#59-theme-switcher-theme-toggletsx)
6. [Reusable UI Primitives (`frontend/src/components/ui/`)](#6-reusable-ui-primitives)
7. [Frontend Client Libraries & Utilities (`frontend/src/lib/`)](#7-frontend-client-libraries--utilities)
8. [Backend Engine Architecture & API Routing](#8-backend-engine-architecture--api-routing)
9. [End-to-End Operational Workflows](#9-end-to-end-operational-workflows)
10. [Component & Engine Reference Matrix](#10-component--engine-reference-matrix)

---

## 1. Executive Summary & Platform Purpose

The **Enterprise Cryptographic Discovery and Agility Tool (ECDAT)** is an automated cybersecurity platform built to transition enterprise infrastructure to **Post-Quantum Cryptography (PQC)**. As quantum computing advances toward cryptanalytically relevant quantum computers (CRQC), asymmetric primitives such as RSA, Diffie-Hellman, and Elliptic Curve Cryptography (ECC) will become vulnerable to Shor's algorithm.

ECDAT delivers a unified web-based interface and analysis engine designed to:
- **Discover** cryptographic assets across four distinct surfaces: Network (live TLS handshakes), Source Code (AST analysis & polyglot scanning), Compiled Binaries (ELF, PE, Mach-O), and Passive Network Traces (PCAP/PCAPNG).
- **Catalog** findings into standardized **CycloneDX 1.6 Cryptographic Bill of Materials (CBOM)** specifications.
- **Score & Reason** over vulnerabilities using **Mosca's Inequality** ($X + Y > Z$), Quantum Risk Indexes, and NIST cryptographic posture standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA).
- **Plan & Automate** migration strategies through agility scoring, timeline roadmaps, and automated source code patch generation.
- **Verify** remediation using differential pre/post migration mathematical proofs to prevent cryptographic regressions.

---

## 2. High-Level Architecture & Tech Stack

ECDAT employs a decoupled, high-throughput client-server architecture:

```
+-----------------------------------------------------------------------------------+
|                                 CLIENT BROWSER                                    |
|  React 19 / Next.js 16 App Router  *  Tailwind CSS v4  *  D3 Canvas / Radix UI   |
+----------------------------------------+------------------------------------------+
                                         | HTTP / REST (Fetch)
                                         v
+-----------------------------------------------------------------------------------+
|                        NEXT.JS 16 STREAMING PROXY ROUTE                           |
|                       (frontend/src/app/api/[...path]/route.ts)                   |
|   - 18 MiB chunked payload buffering for PCAP / Binaries                          |
|   - Dynamic upstream query parameter and header forwarding                       |
|   - Non-JSON upstream error translation (prevents frontend crash on 500/405)      |
+----------------------------------------+------------------------------------------+
                                         | Reverse Proxy (http://127.0.0.1:8000)
                                         v
+-----------------------------------------------------------------------------------+
|                          FASTAPI PYTHON BACKEND ENGINE                            |
|                               (backend/main.py)                                   |
|   - 25+ REST Endpoints (* /api/v1/*)                                              |
|   - Thread-Safe SQLite ScanStore (`data/scans.db`)                                |
|   - Pre-Serialized JSON / YAML Fallback Shims for Zero-Dependency Operation       |
+----------------------------------------+------------------------------------------+
                                         |
     +-----------------------------------+-----------------------------------+
     |                                   |                                   |
     v                                   v                                   v
+--------------------+         +--------------------+         +--------------------+
|  DISCOVERY ENGINES |         |  ANALYSIS & CBOM   |         |  POST-DISCOVERY    |
| - ast_scanner.py   |         | - cbom_generator   |         | - migration_planner|
| - polyglot_scanner |         | - quantum_risk.py  |         | - verifier.py      |
| - binary_scanner.py|         | - asset_graph.py   |         | - patch_engine.py  |
| - pcap_engine.py   |         | - knowledge_graph  |         | - runtime_tracer.py|
| - network_prober.py|         | - custom_crypto.py |         | - demo_flow.py     |
+--------------------+         +--------------------+         +--------------------+
```

### Technology Stack Details

| Layer | Technologies Used | Purpose |
|---|---|---|
| **Frontend Framework** | Next.js 16.1 (App Router), React 19, TypeScript 5 | Component rendering, static optimization, and API proxy routing |
| **Styling & Icons** | Tailwind CSS v4, Lucide React, class-variance-authority | Modern dark/light cyber-themed UI, responsive design tokens |
| **Data Visualization** | `react-force-graph-2d`, HTML5 Canvas, SVG | Interactive D3 topological asset knowledge graph, radar charts |
| **UI Primitives** | Radix UI (`@radix-ui/react-*`), custom accessible wrappers | Modals, tabs, dropdowns, tooltips, sheets, sliders, tables |
| **Backend Framework** | FastAPI, Uvicorn, Starlette, Pydantic | Asynchronous REST API, schema validation, streaming responses |
| **Database / Persistence** | SQLite 3 (`ScanStore`), JSON scan export files | ACID transaction logging of all scans, verification diffs, and evidence |
| **Packet / Binary Analysis** | `scapy`, `pefile`, custom ELF/Mach-O headers, struct unpacking | PCAP dissection, JA3/JA4 fingerprinting, binary section extraction |
| **Cryptographic Standards** | NIST SP 800-52r2, NIST SP 800-131A, FIPS 203/204/205, CNSA 2.0 | Compliance validation rules, algorithm deprecation schedules |

---

## 3. Request Lifecycle & End-to-End Data Flow

The flow of data from user interaction to deep analysis and back proceeds through five distinct stages:

```
[User Action] ---> [Frontend View/Hook] ---> [API Proxy Layer] ---> [FastAPI Router]
                                                                            |
[Visual Update] <--- [React State Cache] <--- [JSON Result] <--- [Analysis Engine + ScanStore]
```

1. **User Initiation**: The user selects a target (e.g., enters a domain for network scan, uploads a `.pcap` or binary file, or enters C/Python source code).
2. **Client Request (`frontend/src/lib/api.ts`)**:
   - `requestApi<T>()` normalizes parameters, sets headers, and issues a `fetch()` request directed to `/api/v1/...`.
   - Multipart form-data payloads (files) or JSON request bodies are packaged with appropriate boundary definitions.
3. **Next.js Proxy (`frontend/src/app/api/[...path]/route.ts`)**:
   - The Catch-All proxy catches `/api/v1/*` requests.
   - For file uploads, it streams chunks (buffered up to 18 MiB) without dropping content.
   - Forwards the request to backend target `http://127.0.0.1:8000/api/v1/*`.
   - Intercepts non-JSON upstream errors (such as 405 Method Not Allowed or 500 Python tracebacks) and transforms them into standard JSON: `{"detail": "<sanitized error message>"}`.
4. **Backend Processing & Analysis (`backend/main.py`)**:
   - FastAPI parses arguments and routes to the dedicated engine module (e.g., `pcap_engine.py`, `ast_scanner.py`, `demo_flow.py`).
   - The engine extracts cryptographic artifacts, computes risk metrics, checks compliance, and compiles an evidence record.
   - The execution is assigned a UUID `scan_id` and saved in the SQLite `ScanStore` along with the raw payload.
5. **Client Response & Visualization**:
   - The frontend parses the resulting JSON payload.
   - Local state triggers UI re-renders: the D3 asset graph adds nodes/edges, the Scan History table records the new scan, the Mosca timeline recalculates, and the status badge updates to `COMPLETED`.

---

## 4. Frontend Application Shell & Routing

The frontend utilizes Next.js App Router architecture rooted in `frontend/src/app/`.

### 4.1 `layout.tsx` (Application Root Layout)
- **Role**: Top-level DOM shell providing fonts, global styles, theme initialization, and accessibility context.
- **Key Functions**:
  - Injects `GeistSans` and `GeistMono` variable fonts for sharp typographic hierarchy.
  - Implements an inline script to synchronously read `localStorage.getItem('theme')` and set the `dark` class on `document.documentElement`, preventing Flash of Unstyled Theme (FOUT).
  - Wraps all children within Radix `TooltipProvider` with a 150ms delay for UI tooltips.

### 4.2 `globals.css` (Design Tokens & Theming)
- **Role**: Master CSS configuration utilizing Tailwind CSS v4 and the OKLCH color space.
- **Features**:
  - Declares theme tokens for primary brand colors (cyber cyan `#00e5ff`, amber warning `#f59e0b`, crimson destructive `#ef4444`, emerald success `#10b981`).
  - Implements custom scrollbar styles (`scrollbar-thin`, `scrollbar-thumb-zinc-800`).
  - Configures CSS animations for scanning pulses, radar sweeps, and loading skeletons.

### 4.3 `page.tsx` (Landing & Showcase Portal)
- **Role**: Public-facing landing page presenting ECDAT’s platform capabilities and health status.
- **Key Sections**:
  - **Hero Header**: Platform title, live version badge, and direct call-to-action buttons ("Launch Dashboard", "View Documentation").
  - **System Diagnostics Bar**: Runs a live probe against `GET /api/v1/health` on initial mount to inform the user of backend availability, engine version, and database connectivity.
  - **Core Capabilities Grid**: 6 interactive feature cards describing Network Discovery, AST Source Scanning, Binary Decomposition, CBOM Generation, Mosca's Equation Engine, and Mathematical Verification.
  - **Compliance Badges**: Highlights adherence to NIST Post-Quantum Standards, FIPS 203/204/205, and NSA CNSA 2.0.

### 4.4 `dashboard/page.tsx` (ECDAT Command Center)
- **Role**: The core operational dashboard managing active scans, navigation tabs, global status indicators, and modal triggers.
- **State Management**:
  - `activeTab`: Switches between 10 operational modes:
    - `"overview"`: Executive summary, KPIs, and interactive D3 asset graph.
    - `"network"`: Live TLS scanner with cipher enumeration and certificate inspection.
    - `"code"`: Static AST & polyglot source code analysis.
    - `"binary"`: PE/ELF/Mach-O binary decompiler and signature scanner.
    - `"pcap"`: Passive packet capture dissection and JA3/JA4 fingerprinting.
    - `"migration"`: Mosca's equation calculator and PQC transition planner.
    - `"verification"`: Closed-loop pre/post migration differential analyzer.
    - `"standards"`: Regulatory compliance posture matrix.
    - `"experimental"`: 6-tab deep cryptographic innovation lab.
    - `"sih_demo"`: Guided 10-step automated end-to-end hackathon demonstration.
  - `isScanning`: Global boolean flag disabling simultaneous triggers and activating spinner animations.
  - `currentScanResult`: Active scan data passed downstream to visualize findings.
  - `scanHistory`: In-memory list of scans supplemented by live polling from `GET /api/v1/scans`.
- **Top Navigation Bar**:
  - Displays breadcrumbs, active system status ("System Ready" vs "Scan Active"), backend connectivity pill, Theme Toggle button, and Quick Scan trigger.

### 4.5 `api/[...path]/route.ts` (Streaming Reverse Proxy)
- **Role**: Next.js Catch-All route serving as a transparent reverse proxy between client browser and FastAPI.
- **Implementation Highlights**:
  - Supports `GET`, `POST`, `PUT`, `DELETE`, `PATCH` methods.
  - Reads raw `request.arrayBuffer()` to support streaming uploads up to 18 MiB for binaries and `.pcap` files without payload truncation.
  - Safely copies headers while dropping `host` to prevent upstream HTTP header collisions.
  - Handles network timeouts (30-second guard) and translates non-JSON upstream errors into standard JSON payloads.

---

## 5. Domain-Specific Dashboard Components

Located in `frontend/src/components/ecdat/`, these components implement the core cryptographic discovery, analysis, and visualization logic.

```
frontend/src/components/ecdat/
├── overview.tsx                 # Executive metrics, D3 asset graph, top weaknesses
├── feature-scan-history.tsx     # Surface-specific filtered scan history with detail drawers
├── evidence-panels.tsx          # Multi-modal cryptographic evidence ledger
├── migration-planner.tsx        # Mosca inequality calculator & 4-phase transition roadmap
├── verification-panel.tsx       # Pre/post differential verification & regression engine
├── standards-panel.tsx          # NIST/FIPS/PCI-DSS/CNSA compliance checklist
├── experimental-hub.tsx         # 6-tool innovations lab (Qubits, Custom Crypto, Patching, etc.)
├── sih-demo-panel.tsx           # 10-step automated SIH evaluation demonstration runner
└── theme-toggle.tsx             # Accessible dark/light mode toggle
```

---

### 5.1 Overview Panel (`overview.tsx`)

#### Purpose
Provides an executive-level single-pane-of-glass overview of the organization's cryptographic posture, combining aggregate risk metrics, high-priority vulnerabilities, and an interactive topological asset graph.

#### Props
```typescript
interface OverviewProps {
  scanResult: ScanResult | null;
  assetGraphData: AssetGraphData | null;
  onNavigateToScan: (surface: string) => void;
  onSelectNode: (nodeId: string) => void;
}
```

#### Key Elements
1. **Executive KPI Cards (4 Cards)**:
   - **Total Cryptographic Assets**: Total count of discovered keys, certificates, ciphers, and algorithms.
   - **Quantum Vulnerability Index**: Percentage of identified assets breakable by Shor's algorithm (e.g., RSA-2048, ECDSA P-256).
   - **Cryptographic Agility Score**: 0-100 rating measuring hardcoded vs dynamically configured cryptography across the infrastructure.
   - **Critical Weaknesses**: Immediate action count of deprecated algorithms (MD5, SHA-1, DES, RC4).
2. **D3 Force-Directed Asset Knowledge Graph**:
   - Built on `react-force-graph-2d` using HTML5 Canvas rendering.
   - **Node Types**: Distinct visual styling and colors for `Host` (cyan), `Service` (indigo), `CipherSuite` (amber), `Certificate` (emerald), `Algorithm` (rose), and `Library` (purple).
   - **Interactive Physics**: Supports pan, zoom, drag, node click (isolating blast radius), and neighbor highlighting.
   - **Custom Node Canvas Painter**: Renders glowing rings around quantum-vulnerable nodes and displays labels at readable zoom thresholds.
3. **Top Weaknesses Table**:
   - Highlights the highest-severity findings with CVSS-like impact scores, affected asset counts, migration urgency, and a 1-click "Plan Migration" action button.

---

### 5.2 Surface-Specific Scan History (`feature-scan-history.tsx`)

#### Purpose
Solves the problem of noisy, mixed scan logs by presenting **isolated, surface-specific scan histories**. When a user operates in the Network tab, they only see Network scans; in the Binary tab, they only see Binary scans.

#### Props
```typescript
interface FeatureScanHistoryProps {
  currentSurface?: 'network' | 'code' | 'binary' | 'pcap' | 'all';
  onSelectScan?: (scan: Scan) => void;
  refreshTrigger?: number;
}
```

#### Key Elements
1. **Surface Filter Tabs**:
   - Quick-toggle pills: `All Scans`, `Network TLS`, `Source Code`, `Compiled Binaries`, `Passive PCAP`.
   - Displays count badges next to each tab (e.g., `Network (14)`).
2. **Scan Record Rows**:
   - Shows Target Name / URL / File Path.
   - Status badge: `COMPLETED` (green), `SCANNING` (animated blue), `FAILED` (red).
   - Relative timestamp and absolute execution time.
   - Summary statistics: Total Findings, Quantum Vulnerable Primitives Count, Risk Level.
3. **Dedicated Surface-Specific Inspectors**:
   - Clicking a scan opens a slide-over or expandable drawer with inspection tailored to that surface:
      - **Network**: Negotiated TLS version, accepted cipher suites list, certificate expiry, ALPN protocols, human-readable Key Exchange primitive (e.g., `ECDHE (Classical)`, `Static RSA`, `Hybrid PQC`), and the **Post-Quantum Threat Assessment Card**:
        - **Post-Quantum Ready (Emerald)**: Displayed when hybrid key exchange (FIPS 203 ML-KEM) is successfully negotiated; session resists retroactive decryption.
        - **Post-Quantum Threat: Vulnerable to Harvest-Now-Decrypt-Later (Red)**: Displayed when the target relies on classical key exchange (ECDHE, DHE, RSA) under TLS 1.2 or TLS 1.3 without PQC. Explicitly marks HNDL Risk Rating as `HIGH` (or `CRITICAL` for broken ciphers like RC4/DES or static RSA lacking forward secrecy) and explains Shor's algorithm risk.
        - **Inconclusive (Amber)**: Displayed only when ML-KEM probe capability is unmeasured or scanner runtime is unavailable.
      - **Code**: Detected source files, AST/regex finding line numbers, vulnerable function calls (`EVP_rc4`, `MD5_Init`).
      - **Binary**: Architecture (x86_64, ARM), binary format (ELF/PE), imported crypto symbols, section entropy scores.
      - **PCAP**: Client/Server IP pairs, packet count, TLS handshake stages, and **JA3/JA4 TLS Fingerprint blocks** with a 1-click clipboard copy button.
4. **Export Action**:
   - Allows instant JSON export of the specific scan record for external reporting.

---

### 5.3 Unified Evidence Viewer (`evidence-panels.tsx`)

#### Purpose
Provides cryptographically verifiable proof of all detections. It aggregates multi-source evidence into standardized `EvidenceRecord` structures, proving *why* an asset was classified as vulnerable.

#### Props
```typescript
interface EvidencePanelProps {
  evidence: EvidenceRecord[];
  activeFilter?: string;
  onExportEvidence?: () => void;
}
```

#### Key Elements
1. **Provenance & Integrity Verification**:
   - Shows the detection method (`STATIC_AST`, `BINARY_SIGNATURE`, `NETWORK_HANDSHAKE`, `PASSIVE_PCAP_SNIFF`).
   - Displays SHA-256 integrity hash of the scanned artifact or network capture to guarantee tamper-proof audit trails.
2. **Confidence Level Meters**:
   - Confidence scoring (`CERTAIN` 1.0, `HIGH` 0.85, `PROBABLE` 0.60, `HEURISTIC` 0.40) based on whether detection was symbol-based, regex-inferred, or runtime-observed.
3. **Code Snippet / Raw Byte Heuristics**:
   - Displays syntax-highlighted code lines where vulnerable calls were identified, complete with line numbers and file paths.
   - Displays hex dumps with highlighted magic bytes for binary detections.
4. **CBOM CycloneDX 1.6 Mapping**:
   - Shows the exact JSON fragment exported into the CycloneDX CBOM component entry.

---

### 5.4 Migration Planner (`migration-planner.tsx`)

#### Purpose
Operationalizes the transition to Post-Quantum Cryptography using mathematical risk modeling and automated timeline generation.

#### Props
```typescript
interface MigrationPlannerProps {
  scanResult: ScanResult | null;
  onApplyPlan?: (plan: MigrationPlan) => void;
}
```

#### Key Elements
1. **Mosca's Inequality Risk Engine**:
   - Implements Mosca's theorem: **If $X + Y > Z$, quantum compromise occurs before migration completes.**
     - $X$ = Data Shelf Life (years data must remain confidential).
     - $Y$ = Migration Time (years required to re-engineer infrastructure to PQC).
     - $Z$ = Collapse Horizon (years until a cryptanalytically relevant quantum computer emerges, typically estimated between 2029–2034).
   - Interactive sliders allow security architects to adjust $X$, $Y$, and $Z$ in real time, dynamically rendering the risk state: **CRITICAL COLLAPSE (Definite Compromise)** vs **SAFE TRANSITION**.
2. **7-Dimensional Cryptographic Agility Radar**:
   - Evaluates agility across 7 core dimensions:
     1. *Algorithm Isolation* (separation of crypto logic from business code)
     2. *Key Length Flexibility* (ability to support larger ML-KEM/ML-DSA keys)
     3. *Configuration Decoupling* (cipher suites defined via config vs hardcoded)
     4. *Protocol Support* (readiness for TLS 1.3 hybrid key exchange)
     5. *Hardware Abstraction* (PKCS#11 / HSM agility)
     6. *Certificate Agility* (support for oversized PQC certificates)
     7. *Automated Testing* (presence of CI/CD regression tests for crypto)
3. **Phased PQC Transition Roadmap**:
   - Generates an actionable 4-phase timeline:
     - **Phase 1: Cryptographic Inventory & Hygiene** (deprecate SHA-1/MD5/DES).
     - **Phase 2: Hybrid Dual-Stack Deployment** (X25519 + ML-KEM-768).
     - **Phase 3: Native Post-Quantum Standards** (FIPS 203 ML-KEM, FIPS 204 ML-DSA).
     - **Phase 4: Legacy Decommissioning** (complete retirement of RSA/ECC).
4. **Plan Exporter**:
   - Generates downloadable Executive Transition Plans in Markdown and structured JSON format.

---

### 5.5 Closed-Loop Verification Panel (`verification-panel.tsx`)

#### Purpose
Executes differential verification comparing a baseline scan with a candidate post-migration scan. It provides mathematical proof that classical vulnerabilities have been eradicated without introducing regressions.

#### Props
```typescript
interface VerificationPanelProps {
  baselineScanId?: string;
  candidateScanId?: string;
  onRunVerification: (baselineId: string, candidateId: string) => Promise<VerificationReport>;
}
```

#### Key Elements
1. **Dual-Scan Selector**:
   - Allows selecting a "Baseline Scan" (pre-migration) and a "Candidate Scan" (post-migration).
2. **Differential Comparison Engine**:
   - **Retired Weaknesses (Green)**: Algorithms successfully removed (e.g., `- RSA-1024`, `- MD5`, `- 3DES`).
   - **Introduced Protections (Blue)**: Quantum-safe algorithms added (e.g., `+ ML-KEM-768`, `+ ML-DSA-65`, `+ AES-256-GCM`).
   - **Persisting Risks (Yellow)**: Unmitigated classical algorithms that still require remediation.
   - **Regressions (Red)**: Deprecated algorithms inadvertently reintroduced or weaker parameters detected.
3. **Formal Verification Verdict**:
   - Displays a prominent status badge:
     - `VERIFIED`: All targeted weaknesses eliminated, zero regressions, PQC standards verified.
     - `REJECTED`: Cryptographic regressions detected or critical weaknesses persist.
     - `INCONCLUSIVE`: Insufficient overlap in scanned attack surface.

---

### 5.6 Cryptographic Standards Panel (`standards-panel.tsx`)

#### Purpose
Audits the discovered cryptographic inventory against major international regulatory and governmental compliance frameworks.

#### Frameworks Evaluated
- **NIST SP 800-52 Rev. 2**: Guidelines for the Selection, Configuration, and Use of TLS Implementations.
- **NIST SP 800-131A Rev. 2**: Transitioning the Use of Cryptographic Algorithms and Key Lengths.
- **NIST FIPS 203**: Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM).
- **NIST FIPS 204**: Module-Lattice-Based Digital Signature Standard (ML-DSA).
- **NIST FIPS 205**: Stateless Hash-Based Digital Signature Standard (SLH-DSA).
- **PCI-DSS v4.0**: Requirement 3 & 4 (Protection of Cardholder Data in transit and at rest).
- **NSA Commercial National Security Algorithm Suite (CNSA 2.0)**: Quantum-resistant requirements for national security systems.
- **RFC 8996**: Deprecation of TLS 1.0 and TLS 1.1.

#### UI Features
- Per-framework compliance progress rings (e.g., `PCI-DSS v4: 87% Compliant`).
- Requirement-by-requirement checklist with rule descriptions and passing/failing assets.
- One-click remediation guidelines explaining exact parameter changes required to achieve 100% compliance.

---

### 5.7 Experimental Innovations Hub (`experimental-hub.tsx`)

#### Purpose
Serves as an advanced R&D laboratory within ECDAT, housing cutting-edge tools for deep cryptographic inspection and automated remediation.

#### The 6 Experimental Tools

```
+-------------------------------------------------------------------------------+
|                           EXPERIMENTAL INNOVATIONS HUB                        |
+-------------------+-------------------+-------------------+-------------------+
|  1. Quantum Qubit |  2. Custom Crypto |  3. Auto-Patch    |  4. eBPF & Runtime|
|     Estimator     |     Benchmarker   |     Engine        |     Tracing       |
+-------------------+-------------------+-------------------+-------------------+
|  5. Passive PCAP  |  6. Binary ML     |                                       |
|     Dissector     |     Classifier    |                                       |
+-------------------+-------------------+---------------------------------------+
```

1. **Quantum Resource Estimator**:
   - Calculates the physical and logical qubits and quantum circuit depth required to break detected public key algorithms via Shor's algorithm.
   - Example outputs:
     - RSA-2048: $\approx 4,098$ logical qubits / $\approx 20$ million physical qubits (surface code error correction).
     - ECC P-256: $\approx 2,330$ logical qubits / $\approx 12$ million physical qubits.
2. **Custom / Proprietary Crypto Detector & Benchmarker**:
   - Detects home-grown or proprietary encryption algorithms ("security through obscurity").
   - Computes **Shannon Entropy**, **Avalanche Effect** ($>50\%$ bit flip variance), and runs **NIST SP 800-22 statistical randomness tests** (frequency, runs, serial tests) to identify weak ciphers.
3. **Automated Source Code Patch Engine**:
   - Generates syntactic Git unified diffs (`.patch`) transforming vulnerable code into quantum-safe equivalents.
   - Example: Replaces OpenSSL `RSA_generate_key_ex` and `EVP_sha1()` with `OQS_KEM_mlkem_768_new()` and `EVP_sha3_256()`.
4. **Runtime & eBPF Tracing**:
   - Dynamically monitors running processes and kernel-level cryptographic hooks.
   - Intercepts calls to OpenSSL (`libcrypto.so`), BoringSSL, and standard C library crypto primitives to catch dynamically generated keys and encrypted channels that bypass static code analysis.
5. **Passive PCAP Dissector**:
   - Deep packet inspection for raw `.pcap` and `.pcapng` network dumps.
   - Decodes ClientHello and ServerHello packets, extracts supported cipher suites, extensions, elliptic curve groups, and computes **JA3/JA3S and JA4 TLS fingerprints**.
6. **Binary ML Classifier**:
   - Employs a machine learning classifier trained on byte n-grams and section entropy to detect compiled cryptographic algorithms embedded inside stripped binaries without symbol tables.

---

### 5.8 SIH 10-Step Interactive Demo (`sih-demo-panel.tsx`)

#### Purpose
An automated, guided demonstration runner built for evaluations (e.g., Smart India Hackathon). It runs a controlled, end-to-end 10-step sequence demonstrating the complete lifecycle of cryptographic discovery, analysis, remediation, and verification.

#### The 10 Automated Steps
1. **Vulnerable Code Scan**: Analyzes sample C/Python code containing legacy algorithms (MD5, DES, RSA-1024).
2. **Polyglot Regex Scan**: Scans cross-language patterns (Java, Go, Rust, C++) to demonstrate multi-language coverage.
3. **Binary Signature Dissection**: Ingests a pre-compiled binary, parsing sections and identifying hardcoded cryptographic keys.
4. **Passive Network Probe**: Emulates an active TLS handshake probe capturing cipher suites and certificates.
5. **CycloneDX 1.6 CBOM Generation**: Combines findings from Steps 1–4 into an authoritative Cryptographic Bill of Materials.
6. **Quantum Risk & Mosca Scoring**: Solves Mosca's equation and assigns an overall Quantum Vulnerability Score.
7. **Asset Graph Construction**: Generates the node-edge topology mapping relationships between hosts, services, and ciphers.
8. **Migration Planning**: Synthesizes the 4-phase PQC migration roadmap with algorithmic substitutions.
9. **Differential Verification**: Compares the baseline scan with a remediated candidate, proving 100% elimination of weaknesses.
10. **Runtime Dynamic Tracing**: Simulates dynamic process execution and traces cryptographic API invocations in real time.

#### UI Controls
- **"Run Full Demo" Button**: Executes all 10 steps sequentially with live progress bars and elapsed timers.
- **"Step-by-Step" Navigation**: Allows evaluators to pause, inspect step inputs and outputs, and execute steps individually.
- **Live Output Terminal**: Streams real-time JSON responses, execution logs, and engine diagnostic messages.
- **Reset Button**: Cleans temporary demo artifacts and restores initial state.

---

### 5.9 Theme Switcher (`theme-toggle.tsx`)

#### Purpose
Provides seamless switching between Dark and Light cyber visual themes.

#### Implementation
- Toggles the `.dark` CSS class on `document.documentElement`.
- Persists the selected state in `localStorage.setItem('theme', mode)`.
- Renders an animated Sun/Moon icon using Lucide React with accessible ARIA labels.

---

## 6. Reusable UI Primitives

Located in `frontend/src/components/ui/`, these components provide atomic, accessible building blocks built on Radix UI and styled with Tailwind CSS:

| Component | File | Base Library | Description & Role in ECDAT |
|---|---|---|---|
| **Alert** | `alert.tsx` | Custom | Callout banners displaying warnings (e.g., Mosca collapse warnings, API disconnections). |
| **Badge** | `badge.tsx` | Custom | Status pills (`COMPLETED`, `HIGH RISK`, `FIPS 203`, `TLS 1.3`, `VERIFIED`). |
| **Button** | `button.tsx` | Custom | Styled interactive buttons with variants (`default`, `destructive`, `outline`, `cyber`, `ghost`). |
| **Card** | `card.tsx` | Custom | Standardized containers with Header, Title, Description, Content, and Footer subcomponents. |
| **Command** | `command.tsx` | `cmdk` | Fast searchable command palette for jumping between dashboard views and filtering scans. |
| **Dialog** | `dialog.tsx` | `@radix-ui/react-dialog` | Modal dialogs for scan triggers, full JSON viewers, and configuration settings. |
| **Input** | `input.tsx` | Custom | Cyber-styled single-line text inputs for target URLs, IP addresses, and search filters. |
| **Input Group** | `input-group.tsx` | Custom | Compound input elements with attached buttons or protocol prefixes (`https://`). |
| **Popover** | `popover.tsx` | `@radix-ui/react-popover` | Floating popovers for contextual information and quick actions. |
| **Separator** | `separator.tsx` | `@radix-ui/react-separator` | Clean horizontal or vertical divider lines between dashboard panels. |
| **Sheet** | `sheet.tsx` | `@radix-ui/react-dialog` | Slide-over side drawers for detailed scan inspection and raw evidence viewing. |
| **Skeleton** | `skeleton.tsx` | Custom | Animated pulse placeholder cards displayed while scans or graphs are loading. |
| **Slider** | `slider.tsx` | `@radix-ui/react-slider` | Dual/single thumb sliders used in Mosca's inequality calculator ($X$, $Y$, $Z$ years). |
| **Table** | `table.tsx` | Custom | Accessible, striped tabular displays for scan histories, ciphers, and evidence records. |
| **Tabs** | `tabs.tsx` | `@radix-ui/react-tabs` | Tab switcher controlling main dashboard views and sub-tool panels. |
| **Textarea** | `textarea.tsx` | Custom | Multi-line code input areas for pasting raw C, Python, or Go source code for AST scanning. |
| **Toast** | `toast.tsx` | Custom | Ephemeral notifications confirming scan completions, clipboard copies, or export actions. |
| **Tooltip** | `tooltip.tsx` | `@radix-ui/react-tooltip` | Hover tooltips explaining complex cryptographic terms, CVSS scores, and algorithm types. |

---

## 7. Frontend Client Libraries & Utilities

Located in `frontend/src/lib/`:

### 7.1 `api.ts`
The typed API client and canonical TypeScript type definitions:
- **`requestApi<T>(path, options)`**: Core fetch wrapper handling URL joining, headers, JSON serialization, and error trapping.
- **Core Type Interfaces**:
  - `Scan`: Metadata representation of a historical scan (`id`, `surface`, `target`, `status`, `created_at`, `findings_count`, `risk_score`).
  - `ScanResult`: Comprehensive output payload including discovered algorithms, quantum risks, agility score, and raw logs.
  - `AssetGraphData`: D3 graph representation (`nodes: GraphNode[]`, `links: GraphLink[]`).
  - `EvidenceRecord`: Cryptographic provenance record (`source`, `confidence`, `sha256`, `snippet`).
  - `VerificationReport`: Pre/post migration differential result (`status`, `retired`, `introduced`, `regressions`).
  - `SihDemoExecution`: Multi-step tracking model for the automated 10-step demo.
  - `PcapSession`: Decoded packet capture metrics and TLS fingerprints (`ja3`, `ja4`, `ciphers`).

### 7.2 `migration.ts`
- Encapsulates client-side migration planning helpers, standard PQC algorithm replacement tables (e.g., `RSA-2048 -> ML-KEM-768`, `ECDSA-P256 -> ML-DSA-65`), and Mosca timeline formatting logic.

### 7.3 `utils.ts`
- **`cn(...inputs)`**: Combines `clsx` and `tailwind-merge` to allow conditional, conflict-free Tailwind CSS class assignment.

---

## 8. Backend Engine Architecture & API Routing

The FastAPI backend (`backend/main.py`) provides 25+ REST endpoints interfacing with modular specialized engines in `backend/engine/`:

```
backend/
├── main.py                         # Master FastAPI application, CORS, and REST routing
└── engine/
    ├── ast_scanner.py              # Python AST walker & C/C++ syntactic parsing
    ├── polyglot_scanner.py         # Multi-language crypto pattern matcher
    ├── binary_scanner.py           # PE/ELF/Mach-O binary header & symbol dissection
    ├── binary_deep.py              # Deep binary analysis, section entropy, string extraction
    ├── pcap_engine.py              # Scapy/struct-based PCAP parser & JA3/JA4 generator
    ├── network_prober.py           # Active TLS handshake prober
    ├── pqc_probe.py                # Quantum-safe hybrid TLS extension prober
    ├── cbom_generator.py           # CycloneDX 1.6 Cryptographic Bill of Materials generator
    ├── quantum_risk.py             # Quantum risk score calculator & Mosca solver
    ├── asset_graph.py              # D3 node-link topological graph generator
    ├── knowledge_graph.py          # Cryptographic relationship knowledge network
    ├── migration_planner.py        # 4-phase transition timeline generator
    ├── pqc_migration.py            # PQC algorithm substitution dictionary
    ├── verifier.py                 # Mathematical differential verification engine
    ├── patch_engine.py             # AST-driven unified diff patch generator
    ├── custom_crypto_detector.py   # Shannon entropy & statistical randomness analyzer
    ├── quantum_estimator.py        # Shor's algorithm qubit/circuit depth calculator
    ├── runtime_tracer.py           # Dynamic process tracer & OpenSSL hook monitor
    ├── ebpf_tracer.py              # Linux eBPF kernel-level crypto probe emulator
    ├── binary_classifier.py        # Byte-level ML classifier for stripped binaries
    ├── scan_store.py               # SQLite thread-safe persistence layer
    └── demo_flow.py                # 10-step SIH automated demonstration orchestrator
```

### Key API Endpoints & Engine Mappings

| Method | Endpoint | Engine Module | Description |
|---|---|---|---|
| `GET` | `/api/v1/health` | `main.py` | Healthcheck returning engine version, status, and DB state. |
| `POST` | `/api/v1/scan/network` | `network_prober.py` | Probes live host/port for TLS versions, ciphers, and certs. |
| `POST` | `/api/v1/scan/code` | `ast_scanner.py`, `polyglot_scanner.py` | Performs AST and regex discovery across source code. |
| `POST` | `/api/v1/scan/binary` | `binary_scanner.py`, `binary_deep.py` | Dissects uploaded compiled executable (PE/ELF/Mach-O). |
| `POST` | `/api/v1/scan/pcap` | `pcap_engine.py` | Dissects uploaded `.pcap` file, extracts TLS handshakes & JA3/JA4. |
| `GET` | `/api/v1/scans` | `scan_store.py` | Returns all historical scans with optional surface filtering. |
| `GET` | `/api/v1/scans/{scan_id}` | `scan_store.py` | Retrieves full details and raw findings for a specific scan. |
| `GET` | `/api/v1/cbom/{scan_id}` | `cbom_generator.py` | Generates a CycloneDX 1.6 CBOM JSON document. |
| `GET` | `/api/v1/graph/{scan_id}` | `asset_graph.py` | Generates node-edge graph data for D3 visualization. |
| `POST` | `/api/v1/migration/plan` | `migration_planner.py` | Calculates Mosca's equation and returns phased roadmap. |
| `POST` | `/api/v1/verify` | `verifier.py` | Runs differential comparison between baseline and candidate scans. |
| `POST` | `/api/v1/experimental/qubit-estimate` | `quantum_estimator.py` | Estimates physical/logical qubits for breaking target cipher. |
| `POST` | `/api/v1/experimental/custom-crypto` | `custom_crypto_detector.py` | Tests custom ciphertext for entropy and randomness flaws. |
| `POST` | `/api/v1/experimental/patch` | `patch_engine.py` | Generates unified `.patch` file replacing legacy crypto. |
| `POST` | `/api/v1/experimental/runtime-trace` | `runtime_tracer.py` | Inspects running process for active crypto library calls. |
| `POST` | `/api/v1/demo/run` | `demo_flow.py` | Executes the 10-step automated SIH demonstration. |

---

## 9. End-to-End Operational Workflows

### 9.1 Workflow: Running a Network / TLS Scan
1. User navigates to the **Network** tab in `dashboard/page.tsx`.
2. User enters `google.com:443` and clicks **Start Scan**.
3. Frontend issues `POST /api/v1/scan/network` through Next.js proxy.
4. `network_prober.py` opens a raw TLS socket, cycles through supported SSL/TLS client hellos, records accepted cipher suites, parses the X.509 certificate chain, and checks for hybrid post-quantum key shares.
5. Findings are stored in `ScanStore` with a new `scan_id`.
6. Frontend updates `currentScanResult`, adds the new scan to `FeatureScanHistory` under the `network` filter, and triggers a graph node addition in `Overview`.

### 9.2 Workflow: Passive PCAP Inspection & JA3/JA4 Fingerprinting
1. User navigates to the **PCAP** tab or the **Experimental Hub -> Passive PCAP** tab.
2. User uploads a `.pcap` capture file.
3. Next.js proxy buffers the binary stream up to 18 MiB and sends it to `POST /api/v1/scan/pcap`.
4. `pcap_engine.py` uses `scapy` and direct binary struct decoding to parse TCP packets, extract TLS ClientHello and ServerHello records, calculate MD5/SHA-256 hashes of client parameters to create **JA3** and **JA4** fingerprints, and tabulate cipher distributions.
5. Findings are rendered in `feature-scan-history.tsx` (PCAP view) with full copy-to-clipboard functionality for JA3/JA4 hashes.

### 9.3 Workflow: Differential Verification Proof
1. User navigates to the **Verification** tab.
2. User selects an older baseline scan (e.g., Scan `#101` with RSA-1024) and a recent candidate scan (e.g., Scan `#108` with ML-KEM-768).
3. User clicks **Verify Remediation**.
4. Backend executes `POST /api/v1/verify` routing to `verifier.py`.
5. The engine executes set-theoretic set difference:
   - Retired Weaknesses = Weaknesses(baseline) \ Weaknesses(candidate)
   - Introduced Protections = Algorithms(candidate) \ Algorithms(baseline)
   - Regressions = New Weaknesses in Candidate
6. If Regressions is empty and target weaknesses are retired, the system outputs verdict `VERIFIED` with a cryptographic verification certificate.

### 9.4 Workflow: Running the SIH 10-Step Demo
1. Evaluator opens the **SIH Demo** tab in `dashboard/page.tsx`.
2. Evaluator clicks **"Run Full Demo"**.
3. Frontend dispatches `POST /api/v1/demo/run` to `demo_flow.py`.
4. The backend sequentially executes:
   - Vulnerable code scan -> Polyglot scan -> Binary dissection -> Network probe -> CBOM generation -> Quantum risk calculation -> Knowledge graph generation -> Migration roadmap -> Differential verification -> Runtime tracer execution.
5. Each step streams progress back to `sih-demo-panel.tsx`, advancing the step indicator, rendering step badges, and populating live output logs.

---

## 10. Component & Engine Reference Matrix

| Frontend Component | File Path | Primary API Endpoint | Backend Engine | Key Output Displayed |
|---|---|---|---|---|
| **OverviewPanel** | `components/ecdat/overview.tsx` | `GET /api/v1/graph/{id}` | `asset_graph.py` | D3 Force Graph, 4 KPI cards, top weaknesses |
| **FeatureScanHistory** | `components/ecdat/feature-scan-history.tsx` | `GET /api/v1/scans` | `scan_store.py` | Surface-filtered history, JA3/JA4, AST findings |
| **EvidenceViewer** | `components/ecdat/evidence-panels.tsx` | `GET /api/v1/scans/{id}` | `evidence_fusion.py` | Multi-source evidence ledger, SHA-256 hashes |
| **MigrationPlanner** | `components/ecdat/migration-planner.tsx` | `POST /api/v1/migration/plan` | `migration_planner.py` | Mosca's equation sliders, 4-phase timeline |
| **VerificationPanel** | `components/ecdat/verification-panel.tsx` | `POST /api/v1/verify` | `verifier.py` | Mathematical differential diff, VERIFIED verdict |
| **StandardsPanel** | `components/ecdat/standards-panel.tsx` | `GET /api/v1/standards/check` | `quantum_risk.py` | NIST/FIPS/PCI-DSS compliance progress rings |
| **ExperimentalHub** | `components/ecdat/experimental-hub.tsx` | `POST /api/v1/experimental/*` | 6 Modular Engines | Qubits, custom crypto, auto-patch diffs, eBPF |
| **SihDemoPanel** | `components/ecdat/sih-demo-panel.tsx` | `POST /api/v1/demo/run` | `demo_flow.py` | 10-step progress runner, live step execution logs |
| **ThemeToggle** | `components/ecdat/theme-toggle.tsx` | N/A (Client DOM) | N/A | Dark / Light theme toggle |
