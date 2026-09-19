# ECDAT Live Demo Guide: 3 Dedicated Node.js Web Applications & In-Code Patching

This guide provides an end-to-end presentation walkthrough for demonstrating ECDAT's cryptographic discovery, risk auditing, and automated in-code patching using **3 dedicated, fully functional Node.js web applications**.

---

## The 3 Dedicated Websites (Node.js Microservices)

| Website | Live URL | Business Functionality | Cryptographic Vulnerabilities (Before Patch) | Remediated Posture (After Patch) |
| :--- | :--- | :--- | :--- | :--- |
| **1. ApexPay**<br>`website1_apex_pay/server.js` | `http://localhost:8081` | • Enterprise Banking & Settlement<br>• Credit Card Payment Checkout<br>• Stored Token Ledger<br>• Live DB Ciphertext Inspector | • **MD5** password hashing (`crypto.createHash('md5')`)<br>• **56-bit DES** card token encryption (`crypto.createCipheriv('des-cbc', ...)`) | • **SHA-256** (FIPS 180-4)<br>• **AES-256-CBC** (FIPS 197)<br>• Live Green Status Badge |
| **2. MedVault**<br>`website2_med_vault/server.js` | `http://localhost:8082` | • Clinical EHR Patient Charts<br>• Digital Prescription Authoring<br>• Doctor Asymmetric Signature<br>• 30-Year HIPAA Retention Audit | • **RSA-1024** doctor signing key (`modulusLength: 1024`)<br>• Harvest Now, Decrypt Later (HNDL) quantum threat | • **RSA-3072** NIST minimum key margin<br>• PQC ML-DSA transition ready<br>• Live Green Status Badge |
| **3. CipherCloud**<br>`website3_cipher_cloud/server.js` | `http://localhost:8083` | • Enterprise Cloud Secret Locker<br>• Encrypted File & Note Storage<br>• Real-time file encryption/decryption<br>• Stored Block Inspector | • **56-bit DES** symmetric encryption<br>• **MD5** file integrity checksums | • **AES-256** authenticated encryption<br>• **SHA-256** file integrity checksums<br>• Live Green Status Badge |

---

## Step 1: Launch All 3 Node.js Websites

In your terminal, run either:
```bash
node demo_servers/run_all.js
# OR
npm run demo:servers
```

All 3 websites boot immediately and are live in your web browser:
- `http://localhost:8081` (ApexPay)
- `http://localhost:8082` (MedVault)
- `http://localhost:8083` (CipherCloud)

Open each in a browser tab. You will see:
- Real, modern user interfaces with interactive forms, dashboards, and live transaction logs.
- Prominent red security alerts: `VULNERABILITY DETECTED` with live cryptographic inspection panels.

---

## Step 2: (Optional) Expose Publicly via Cloudflare Tunnel

To show external network scanning to judges or remote evaluators:
```bash
# In a separate terminal, tunnel any of the websites:
cloudflared tunnel --url http://localhost:8081
```
Cloudflare will give you a public URL (e.g., `https://example-subdomain.trycloudflare.com`).
You can paste this URL into ECDAT's **Network Scan** to show external edge discovery.

---

## Step 3: Demonstrate Vulnerability Discovery in ECDAT

1. Open the **ECDAT Dashboard** at `http://localhost:3000`.
2. Go to **Scan Mode: Source Code**.
3. Point to the `demo_servers/` directory:
   - ECDAT analyzes the AST of all 3 websites.
   - Flags `MD5` password hashing with `CRITICAL` severity in ApexPay.
   - Flags `DES-56` symmetric ciphers in ApexPay and CipherCloud.
   - Flags `RSA-1024` quantum-vulnerable keys in MedVault.
4. Open the **Blast Radius & Post-Quantum Assessment**:
   - Demonstrates the HNDL risk for MedVault's 30-year clinical records.

---

## Step 4: Demonstrate Live In-Code Patching

You can demonstrate patching in two impressive ways:

### Option A: Via Terminal (Enterprise CI/CD Automation)
1. **Show the Audience the Dry-Run Preview**:
   ```bash
   python -m backend patch --path demo_servers
   ```
   - ECDAT inspects the files, executes differential regression tests in memory, and prints colorized unified diffs.
   - Point out to the audience: *"ECDAT has mathematically proven the patch is safe before altering any code."*

2. **Apply the Patches Live**:
   ```bash
   python -m backend patch --path demo_servers --apply
   ```
   - Automatically creates `.bak` safety backup copies.
   - Rewrites the code with FIPS-compliant primitives.
   - In-memory re-scan confirms: **`WEAKNESS ELIMINATED (0 findings remaining)`**.

### Option B: Via Web Dashboard (Interactive 1-Click UI)
1. Go to **Experimental Hub $\to$ Auto-Patch Engine**.
2. Target: `demo_servers/website1_apex_pay/app.py`.
3. Click **Generate Patch & Execute Test** $\to$ inspect the unified diff.
4. Click **Apply Directly to File**:
   - Shows live confirmation and backup location.

---

## Step 5: The "Grand Reveal" in the Browser

Switch back to the browser tabs for the 3 websites and hit **Refresh (`Ctrl+R` / `F5`)**:

1. **ApexPay (`http://localhost:8081`)**:
   - The red vulnerability badge changes to a green glowing badge: `SECURITY: PATCHED (SHA-256 & AES-256)`.
   - Submit a new payment transaction: the live DB inspector confirms the card token is now encrypted with **AES-256-CBC**!
2. **MedVault (`http://localhost:8082`)**:
   - The red alert changes to: `POSTURE: NIST 3072-BIT RECOVERY`.
   - Issue a new prescription: Dr. Thorne's digital signature is generated with a **3072-bit NIST compliant key**.
3. **CipherCloud (`http://localhost:8083`)**:
   - The badge changes to: `SECURITY: AES-256 & SHA-256 SECURED`.
   - Upload a new document: encrypted with **AES-256** and checksummed with **SHA-256**.
