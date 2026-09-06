# ECDAT: Enterprise Cryptographic Discovery & Analysis Tool

<div align="center">

[![SIH 2026](https://img.shields.io/badge/Smart%20India%20Hackathon-2026-orange.svg?style=flat-square)](https://sih.gov.in)
[![Problem Statement](https://img.shields.io/badge/Problem%20Statement-SIH26164-blue.svg?style=flat-square)](https://sih.gov.in)
[![Target Agency](https://img.shields.io/badge/Agency-NTRO-red.svg?style=flat-square)](https://ntro.gov.in)
[![Next.js 16](https://img.shields.io/badge/Frontend-Next.js%2016-black.svg?style=flat-square&logo=next.js)](https://nextjs.org)
[![FastAPI](https://img.shields.io/badge/Backend-FastAPI%200.100+-009688.svg?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?style=flat-square&logo=docker)](https://docker.com)
[![CycloneDX 1.6](https://img.shields.io/badge/CBOM-CycloneDX%20v1.6%20(ECMA--424)-green.svg?style=flat-square)](https://cyclonedx.org)
[![NIST PQC](https://img.shields.io/badge/NIST-FIPS%20203%20%7C%20204%20%7C%20205-purple.svg?style=flat-square)](https://csrc.nist.gov/projects/post-quantum-cryptography)

**A high-assurance, defense-grade cybersecurity posture management platform for discovering cryptographic assets, identifying Harvest Now Decrypt Later (HNDL) quantum exposures, and automating migration to NIST Post-Quantum Cryptography standards.**

[Features](#-key-capabilities) • [Architecture](#-system-architecture) • [Quickstart (Any OS)](#-quickstart-run-on-any-os) • [Live Testing](#-live-demo--test-targets) • [API Documentation](#-api-endpoints)

</div>

---

## 🎯 Context & Mission (SIH26164 · NTRO)

Adversaries are actively intercepting and storing encrypted government and defense communications in **Harvest Now, Decrypt Later (HNDL)** campaigns, preparing to decrypt them as soon as a **Cryptanalytically Relevant Quantum Computer (CRQC)** emerges.

Developed for **Problem Statement 26164** by the **National Technical Research Organisation (NTRO)**, **ECDAT** bridges the gap between low-level cryptographic analysis and strategic defense readiness. It provides autonomous discovery across network perimeters, multi-language source code, and compiled IoT/firmware binaries, computing exact quantum risk deficits via **Mosca's Theorem** and exporting standards-compliant **CycloneDX v1.6 CBOMs**.

---

## ⚡ Key Capabilities

### 1. 🌐 Dynamic TLS Prober & Multi-Factor HNDL Engine
* Executes real raw TCP handshakes with strict timeouts and permissive OpenSSL contexts to enumerate legacy ciphers (RC4, 3DES, EXPORT).
* Deconstructs X.509 certificates (SANs, CA hierarchy, validity, public key algorithms: RSA, ECDSA, Ed25519).
* **Multi-Factor Risk Synthesis**: Evaluates KEX, bulk cipher, and certificate auth rather than blindly assigning high risk to modern TLS 1.3 endpoints.

### 2. 💻 Polyglot Multi-Language Static Code Scanner
* Audits source code across **5 enterprise languages**: **Python**, **Java** (Spring/JCE), **C / C++** (OpenSSL EVP), **Go** (`crypto`), and **Node.js**.
* Pinpoints AST sinks with exact line numbers and Common Weakness Enumeration tags (**CWE-326, CWE-327, CWE-328**).
* Generates language-specific, post-quantum ready drop-in remediation patches (AES-256-GCM, SHA-256, RSA-3072 / ML-KEM).

### 3. 🔬 Binary & Firmware Cryptographic Constant Scanner (Module 10)
* Designed for closed-source IoT firmware, `.elf`, and `.so` libraries where source code is unavailable.
* Locates compiled substitution tables (**AES Rijndael S-Boxes**, **DES Initial Permutation tables**), hash state words (MD5, SHA-1, SHA-256), and embedded PEM private keys.
* Calculates sliding-window **Shannon Byte Entropy** ($0.0 - 8.0$ bits) to isolate encrypted or packed blocks.

### 4. 🕸️ Cryptographic Knowledge Graph & Blast Radius
* Modeled on a directed graph topology using `NetworkX` (`App → Service → Protocol → Primitive → Certificate`).
* Executes ancestral graph traversal (`nx.ancestors`) to isolate the exact blast radius of compromised cryptographic primitives across the enterprise.

### 5. 🧭 Cryptographic Agility Index (CAI) Framework (Module 7)
* Mathematical scoring framework ($0.00 - 1.00$) evaluating:
  1. *Primitive Decoupling* (Configuration-driven vs. hardcoded)
  2. *Provider & API Abstraction* (JCE / OpenSSL 3.0 Providers)
  3. *KEM Modularity* (Separation of key exchange from bulk encryption)
  4. *Certificate Lifecycle Automation* (ACME / Vault)

### 6. ⚛️ Mosca Quantum Urgency Engine & PQC Gantt Roadmap
* Implements Mosca's Theorem ($X + Y > Z$) to compute exact quantum exposure deficits.
* Generates an executive 3-phase engineering migration timeline with dynamically calculated person-months and INR budget.
* Aligned with finalized NIST standards: **FIPS 203 (ML-KEM)**, **FIPS 204 (ML-DSA)**, and **FIPS 205 (SLH-DSA)**.

### 7. 📜 CycloneDX v1.6 (ECMA-424) CBOM Generator
* Generates official Cryptographic Bill of Materials in JSON format capturing all network, code, and binary findings with NIST Quantum Security Levels ($0 - 5$).

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        DISCOVERY SOURCES (INGRESS)                     │
├──────────────────────────┬────────────────────────┬────────────────────┤
│   Network TLS Prober     │  Polyglot AST Scanner  │ Binary / Firmware  │
│  Raw OS Sockets & OpenSSL│ Python, Java, C, Go, JS│ S-Boxes & Entropy  │
└────────────┬─────────────┴───────────┬────────────┴─────────┬──────────┘
             │                         │                      │
             ▼                         ▼                      ▼
┌────────────────────────────────────────────────────────────────────────┐
│                       CENTRAL INTELLIGENCE CORE                        │
├────────────────────────────────────────────────────────────────────────┤
│ • Asynchronous FastAPI Controller (Non-blocking I/O)                   │
│ • Cryptographic Knowledge Graph (CKG) via NetworkX Directed Graph      │
│ • Multi-Factor HNDL Exposure Derivation Engine                         │
│ • Mosca Quantum Risk Deficit Engine (X + Y > Z)                        │
│ • Cryptographic Agility Index (CAI) Framework (4 Pillars)              │
│ • Executive PQC Migration Gantt Simulator                              │
└──────────────────────────────┬─────────────────────────────────────────┘
                               │
                               ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   DEFENSE OUTPUTS & STANDARDS COMPLIANCE               │
├──────────────────────────┬────────────────────────┬────────────────────┤
│ CycloneDX v1.6 (ECMA-424)│ NIST FIPS 203/204/205  │ Drop-In Quantum    │
│ CBOM Standard JSON Export│ NSA CNSA 2.0 & NQM Plan│ Code Patches       │
└──────────────────────────┴────────────────────────┴────────────────────┘
```

---

## 🚀 Quickstart: Run on ANY Operating System

ECDAT is cross-platform and can be executed via Docker (recommended) or native scripts.

### Option 1: 🐳 Docker & Docker Compose (Universal - Any OS)
Runs with a single command on **Windows**, **macOS**, and **Linux**:

```bash
# Clone the repository
git clone https://github.com/srujan1828-maker/ECDAT.git
cd ECDAT

# Start both frontend and backend in containers
docker compose up --build
```
* **Frontend UI**: `http://localhost:3000`
* **Backend API Docs**: `http://localhost:8000/docs`

---

### Option 2: 🪟 Windows (One-Click Batch File)
Requires **Python 3.10+** and **Node.js 18+**:

```cmd
# Double click run.bat or run from terminal:
run.bat
```
* Automatically creates `.venv`, installs backend dependencies, starts FastAPI on `:8000`, installs npm packages, and starts Next.js on `:3000`.

---

### Option 3: 🐧 Linux / 🍎 macOS (Bash Script)
Requires **Python 3.10+** and **Node.js 18+**:

```bash
# Make script executable and launch
chmod +x run.sh
./run.sh
```
* Handles virtual environment setup, installs dependencies, launches background processes, and cleanly terminates on `Ctrl+C`.

---

### Option 4: 🛠️ Manual Step-by-Step Setup

<details>
<summary>Click to view manual startup commands</summary>

#### 1. Backend Setup
```bash
cd backend
python -m venv ../.venv

# Activate virtual environment:
# Windows:
..\.venv\Scripts\activate
# Linux/macOS:
source ../.venv/bin/activate

pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000 --reload
```

#### 2. Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

</details>

---

## 🧪 Live Demo & Test Targets

| Tab | Action / Input | Expected Result |
| :--- | :--- | :--- |
| **Network Prober** | Probe `google.com` | Detects `TLSv1.3`, `AES-256-GCM`, ephemeral `ECDHE (X25519/P-256)`, derives **`MEDIUM`** HNDL risk (Grover resistant baseline). |
| **Network Prober** | Probe `rc4.badssl.com` | Detects `TLS_RSA_WITH_RC4_128_SHA`, flags **`CRITICAL`** static RSA exposure (catastrophic Shor risk). |
| **Polyglot Scanner** | Switch language to `Java` | Audits Java Spring code; identifies `MessageDigest MD5`, `Cipher DES/ECB`, and generates Java drop-in remediation. |
| **Binary & Firmware** | Click *Triage Synthetic Firmware* | Computes Shannon entropy (7.4/8.0 bits), identifies AES S-Box table at offset `0x000001B0` and DES tables. |
| **Agility & Roadmap** | Review CAI Scorecard | Computes CAI score across 4 pillars and visualizes a 3-phase PQC Migration Gantt timeline with budget in INR. |
| **CBOM & Risk** | Adjust Mosca sliders ($X=10, Y=4, Z=8$) | Live equation computes $10+4 > 8 \implies \text{EXPOSED}$. Exports standards-compliant **CycloneDX v1.6 CBOM**. |

---

## 🔌 API Endpoints

FastAPI provides an interactive OpenAPI / Swagger specification at `http://localhost:8000/docs`.

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/scan/network` | Conducts dynamic TLS handshake and derives multi-factor HNDL exposure. |
| `POST` | `/api/scan/code` | Executes polyglot static AST analysis for Python, Java, C/C++, Go, and JS. |
| `POST` | `/api/scan/binary` | Analyzes compiled binaries/firmware for S-boxes, constants, and entropy. |
| `POST` | `/api/agility/evaluate` | Evaluates Cryptographic Agility Index (CAI) across 4 architectural pillars. |
| `POST` | `/api/migration/simulate`| Computes 3-phase PQC Migration Gantt timeline, person-months, and budget. |
| `POST` | `/api/risk/mosca` | Calculates Mosca's Theorem quantum risk deficit ($X + Y > Z$). |
| `POST` | `/api/export/cbom` | Generates official CycloneDX v1.6 (ECMA-424) CBOM JSON document. |
| `GET`  | `/api/demo/overview` | Retrieves live Cryptographic Knowledge Graph topology and KPIs. |

---

## 🛡️ Regulatory & Defense Compliance Alignment

* **NSA CNSA 2.0**: Aligned with Commercial National Security Algorithm Suite mandates requiring transition to ML-KEM and ML-DSA by 2030.
* **NIST SP 800-131A**: Enforces deprecation of legacy cryptographic keys offering $< 112$ bits of security (RSA-1024, single DES, SHA-1).
* **NIST FIPS 203, 204, 205**: Maps discovered primitives directly to finalized Post-Quantum Cryptography standards (ML-KEM, ML-DSA, SLH-DSA).
* **India National Quantum Mission (NQM)**: Supports national critical infrastructure quantum preparedness through automated CBOM inventory and agility modeling.

---

## 📁 Repository Structure

```
ECDAT/
├── backend/                  # FastAPI Backend Core
│   ├── engine/
│   │   ├── agility_engine.py      # Module 7: CAI Scoring Model
│   │   ├── ast_scanner.py         # Python AST Visitor & Sink Detector
│   │   ├── binary_scanner.py      # Module 10: S-Box & Entropy Disassembler
│   │   ├── cbom_generator.py      # Module 8: CycloneDX v1.6 CBOM Generator
│   │   ├── knowledge_graph.py     # Modules 3 & 4: NetworkX Graph & Blast Radius
│   │   ├── migration_simulator.py # PQC Gantt Timeline & Budget Simulator
│   │   ├── network_prober.py      # Module 2: TLS Socket & HNDL Engine
│   │   ├── polyglot_scanner.py    # Module 1: Python/Java/C/Go/JS AST Scanner
│   │   └── quantum_risk.py        # Module 6: Mosca's Theorem Engine
│   ├── main.py               # REST API Gateway & Route Controllers
│   ├── requirements.txt      # Python Dependencies
│   └── Dockerfile            # Backend Containerization
├── frontend/                 # Next.js 16 Web Dashboard
│   ├── src/
│   │   ├── app/
│   │   │   ├── globals.css        # Tailwind v4 Dark-Mode Tokens
│   │   │   ├── layout.tsx         # Root Layout & Theme Configuration
│   │   │   └── page.tsx           # Full Integrated ECDAT Dashboard UI
│   │   ├── components/ui/         # Base UI Component Library
│   │   └── lib/api.ts             # API Client & Telemetry Bridge
│   ├── package.json          # Node Dependencies
│   └── Dockerfile            # Frontend Containerization
├── docker-compose.yml        # Multi-Container Orchestration (Any OS)
├── requirements.txt          # Root Python Dependency Manifest
├── run.bat                   # Windows One-Click Launch Script
├── run.sh                    # Linux / macOS Cross-Platform Launch Script
├── .gitignore                # Production Git Exclusion Rules
└── README.md                 # Project Documentation
```

---

## 📜 License & SIH Attribution

Developed for **Smart India Hackathon 2026** under **Problem Statement SIH26164** for the **National Technical Research Organisation (NTRO)**.

Licensed under the [Apache-2.0 License](LICENSE).
