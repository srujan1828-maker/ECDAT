# 🚀 ECDAT Demo Websites - 5-Minute Deployment Guide

All 3 demo websites are fully standalone, production-ready Node.js web applications with zero external database dependencies. They can be deployed anywhere in under 5 minutes.

---

## ⚡ Option 1: Live Cloudflare Public HTTPS Tunnels (Fastest · 30 Seconds)

To expose all 3 websites on live public HTTPS URLs (e.g. for sharing with judges or testing on your mobile phone):

```bash
# From project root:
npm run demo:deploy

# Or directly:
node demo_servers/tunnel_deploy.js
```

### What This Does:
1. Starts the 3 websites locally on ports 8081, 8082, 8083.
2. Automatically establishes secure Cloudflare Quick Tunnels.
3. Outputs **3 live public HTTPS URLs** with green checkmarks:
   - 💳 **ApexPay Banking**: `https://[random].trycloudflare.com`
   - 🏥 **MedVault EHR**: `https://[random].trycloudflare.com`
   - ☁️ **CipherCloud Storage**: `https://[random].trycloudflare.com`
4. **Zero configuration** — no Cloudflare account, domain name, or login required.

---

## 🐳 Option 2: Docker Compose (1 Command)

Deploy all 3 applications in isolated Docker containers with automatic restart:

```bash
# Build and run containers in background:
docker compose -f demo_servers/docker-compose.yml up -d --build
```

### Verify Container Status:
```bash
docker ps
```

### Access Ports:
- ApexPay: `http://localhost:8081`
- MedVault: `http://localhost:8082`
- CipherCloud: `http://localhost:8083`

---

## ☁️ Option 3: Cloud Deployment on Render.com / Railway / Fly.io

Each website has its own dedicated `package.json` and `Dockerfile`:
- `demo_servers/website1_apex_pay/`
- `demo_servers/website2_med_vault/`
- `demo_servers/website3_cipher_cloud/`

### Render.com (1-Click Blueprint):
1. Push your repository to GitHub.
2. Go to **[dashboard.render.com/blueprints](https://dashboard.render.com/blueprints)**.
3. Select your repository.
4. Render automatically detects [`demo_servers/render.yaml`](./render.yaml) and creates all 3 web services.

### Railway / Fly.io / Heroku:
Deploy each folder independently:
- Root directory: `demo_servers/website1_apex_pay`
- Start command: `node --openssl-legacy-provider server.js`
- Port: `process.env.PORT` (automatically mapped)

---

## 💻 Option 4: Local Orchestration (Default)

```bash
# Run all 3 servers in a single terminal:
node demo_servers/run_all.js
```

---

## 🎯 Verification Matrix

| Target Website | Local Port | Key Vulnerabilities (Before Patch) | Post-Quantum / Remediated Standard |
| :--- | :--- | :--- | :--- |
| **ApexPay** | `http://localhost:8081` | MD5 Passwords, 56-bit DES card token encryption | FIPS 180-4 SHA-256, FIPS 197 AES-256 |
| **MedVault** | `http://localhost:8082` | 1024-bit RSA digital prescription signing | FIPS 186-5 RSA-3072 / ML-DSA Post-Quantum |
| **CipherCloud** | `http://localhost:8083` | DES-CBC file encryption, MD5 checksum | AES-256-GCM authenticated encryption |
