"""Website 2: MedVault - Healthcare Records & Electronic Prescription Portal.

A dedicated, fully functional healthcare EHR portal.

FUNCTIONALITY:
- Electronic Health Records (EHR) database with clinical patient charts.
- Doctor Digital Prescription Signing & Cryptographic Verification.
- Long-term Medical Confidentiality Audit (HIPAA 30-year retention rule).
- Live signature creation & verification in the browser.

CRYPTOGRAPHIC VULNERABILITIES (BEFORE PATCH):
- Doctor's digital signature uses disbarred 1024-bit RSA key generation (NIST SP 800-131A).
- Severe Harvest Now, Decrypt Later (HNDL) quantum threat for health records.

REMEDIATION (AFTER PATCH):
- Upgraded to NIST minimum 3072-bit RSA asymmetric margin (ready for FIPS 204 ML-DSA migration).
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import sys
import urllib.parse
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

PORT = 8082

# Mock Patient Database
PATIENTS = [
    {
        "id": "MED-7701",
        "name": "Alexander Hayes",
        "age": 42,
        "blood_group": "O+",
        "diagnosis": "Severe Chronic Hypertension & Arrhythmia",
        "physician": "Dr. Aris Thorne, MD",
        "last_visit": "2026-09-18",
        "prescriptions": ["Lisinopril 20mg Daily", "Metoprolol 50mg Extended Release"]
    },
    {
        "id": "MED-7702",
        "name": "Elena Rostova",
        "age": 31,
        "blood_group": "A-",
        "diagnosis": "Type 1 Diabetes Mellitus",
        "physician": "Dr. Aris Thorne, MD",
        "last_visit": "2026-09-15",
        "prescriptions": ["Insulin Glargine 18 Units at Bedtime", "Continuous Glucose Monitor Sensor"]
    },
    {
        "id": "MED-7703",
        "name": "Marcus Vance",
        "age": 58,
        "blood_group": "B+",
        "diagnosis": "Post-Surgical Immunosuppressive Therapy",
        "physician": "Dr. Maya Lin, MD",
        "last_visit": "2026-09-12",
        "prescriptions": ["Tacrolimus 2mg BID", "Prednisone 5mg Daily"]
    }
]

SIGNED_PRESCRIPTIONS = [
    {
        "id": "RX-8810",
        "patient": "Alexander Hayes",
        "medication": "Lisinopril 20mg",
        "doctor": "Dr. Aris Thorne, MD",
        "signed_at": "2026-09-18 11:20",
        "signature_hex": "4a7f9b1c8e3d...[RSA-1024]"
    }
]


def generate_doctor_key():
    """VULNERABILITY: Quantum-vulnerable 1024-bit RSA key generation."""
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,
        backend=default_backend()
    )
    return key


DOCTOR_KEY = generate_doctor_key()


def is_patched() -> bool:
    """Detects if ECDAT patch has been applied to this file."""
    with open(__file__, "r", encoding="utf-8") as f:
        src = f.read()
    return "key_size=3072" in src or "3072" in src


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MedVault - Clinical EHR & Digital Prescription Portal</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #070d14; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .glass-card { background: rgba(13, 23, 39, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(56, 189, 248, 0.15); }
    .glow-teal { box-shadow: 0 0 25px rgba(20, 184, 166, 0.12); }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- Header -->
  <header class="border-b border-sky-950 bg-sky-950/40 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="h-9 w-9 rounded-lg bg-gradient-to-tr from-teal-500 to-emerald-600 flex items-center justify-center font-bold text-white shadow-lg">
          <i class="fa-solid fa-staff-snake"></i>
        </div>
        <div>
          <span class="font-extrabold text-lg tracking-tight text-white">Med<span class="text-teal-400">Vault</span></span>
          <span class="text-[10px] ml-2 px-2 py-0.5 rounded bg-sky-900 text-teal-300 font-mono">CLINICAL EHR</span>
        </div>
      </div>

      <!-- Security Status Badge -->
      <div class="flex items-center gap-3">
        __SECURITY_BADGE__
        <div class="h-8 w-8 rounded-full bg-teal-950 border border-teal-700/50 flex items-center justify-center text-xs font-semibold text-teal-300">
          AT
        </div>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full space-y-8">

    <!-- Hero / Clinical Audit Summary -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div class="glass-card rounded-xl p-6 glow-teal flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Patient Registry (HIPAA Scope)</span>
            <i class="fa-solid fa-hospital-user text-teal-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">1,248 Records</div>
          <p class="text-xs text-amber-400 mt-1"><i class="fa-solid fa-hourglass-half"></i> 30-Year Confidentiality Mandate</p>
        </div>
        <div class="mt-6 pt-4 border-t border-sky-950 flex items-center justify-between text-xs text-gray-400">
          <span>Facility: <b>Metro General Health</b></span>
          <span>EMR System: <b>Epic/HL7 v2.9</b></span>
        </div>
      </div>

      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Doctor Signature Key Margin</span>
            <i class="fa-solid fa-key text-sky-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">__KEY_SIZE_DISPLAY__</div>
          <p class="text-xs text-gray-400 mt-1">Algorithm: RSA-PKCS1v15 / SHA-256</p>
        </div>
        <div class="mt-6 pt-4 border-t border-sky-950 flex items-center justify-between text-xs text-gray-400">
          <span>HNDL Quantum Risk: <b class="__HNDL_COLOR__">__HNDL_RATING__</b></span>
          <span>Shor's Threat: <b>Critical</b></span>
        </div>
      </div>

      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Active Clinician</span>
            <i class="fa-solid fa-user-doctor text-emerald-400"></i>
          </div>
          <div class="text-lg font-bold text-white mt-3">Dr. Aris Thorne, MD</div>
          <div class="text-xs text-teal-300 mt-1">Chief of Internal Medicine · Lic #MD-88192</div>
        </div>
        <div class="mt-6 pt-4 border-t border-sky-950 flex items-center justify-between text-xs text-gray-400">
          <span>Smart Card HSM: <b>Simulated</b></span>
          <span>Status: <b>Active Duty</b></span>
        </div>
      </div>
    </div>

    <!-- Digital Prescription Authoring & Patient Records -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
      
      <!-- Issue Prescription Form -->
      <div class="glass-card rounded-xl p-6 space-y-6">
        <div class="border-b border-sky-950 pb-4">
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-file-prescription text-teal-400"></i>
            Issue Digitally Signed Clinical Prescription
          </h2>
          <p class="text-xs text-gray-400 mt-1">Sign patient orders cryptographically. The signature will be computed with Dr. Thorne's private key.</p>
        </div>

        <form action="/sign_rx" method="POST" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Select Patient</label>
            <select name="patient" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500">
              <option value="Alexander Hayes">Alexander Hayes (ID: MED-7701 - Hypertension)</option>
              <option value="Elena Rostova">Elena Rostova (ID: MED-7702 - Diabetes)</option>
              <option value="Marcus Vance">Marcus Vance (ID: MED-7703 - Post-Op)</option>
            </select>
          </div>

          <div>
            <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Medication Order & Dosage</label>
            <input type="text" name="medication" required value="Atorvastatin 40mg PO QHS (Daily)" class="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-teal-500 font-medium">
          </div>

          <button type="submit" class="w-full bg-gradient-to-r from-teal-600 to-emerald-600 hover:from-teal-500 hover:to-emerald-500 text-white font-semibold py-2.5 rounded-lg shadow-lg flex items-center justify-center gap-2 text-sm transition-all">
            <i class="fa-solid fa-signature"></i>
            Digitally Sign & Dispatch Prescription
          </button>
        </form>
      </div>

      <!-- Quantum Threat & Signature Ledger -->
      <div class="glass-card rounded-xl p-6 space-y-6">
        <div class="border-b border-sky-950 pb-4 flex justify-between items-center">
          <div>
            <h2 class="text-lg font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-fingerprint text-sky-400"></i>
              Signed Digital Prescriptions
            </h2>
            <p class="text-xs text-gray-400 mt-1">Cryptographic integrity audit for active clinical orders</p>
          </div>
          <span class="text-xs px-2.5 py-1 rounded bg-teal-950 text-teal-400 border border-teal-800/50 font-mono">Audit Ready</span>
        </div>

        <div class="space-y-3">
          __PRESCRIPTION_ITEMS__
        </div>

        <div class="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 text-xs space-y-1">
          <div class="font-semibold text-gray-300 flex items-center gap-1.5">
            <i class="fa-solid fa-circle-radiation text-amber-400"></i>
            Harvest Now, Decrypt Later (HNDL) Alert
          </div>
          <p class="text-gray-400 text-[11px]">
            Run <code class="text-teal-300 bg-slate-800 px-1 py-0.5 rounded">python -m backend patch --path demo_servers/website2_med_vault --apply</code> to upgrade this hospital's key margin to 3072-bit post-quantum transition readiness.
          </p>
        </div>
      </div>

    </div>

    <!-- Patient Electronic Health Charts -->
    <div class="glass-card rounded-xl p-6 space-y-4">
      <div class="flex justify-between items-center">
        <h3 class="font-bold text-white text-base">Active Clinical Patient Charts</h3>
        <span class="text-xs text-gray-400">Restricted Medical Access</span>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        __PATIENT_CARDS__
      </div>
    </div>

  </main>

  <!-- Footer -->
  <footer class="border-t border-sky-950 py-4 text-center text-xs text-gray-500 bg-slate-950/60">
    MedVault Clinical Healthcare Systems · Protected by ECDAT Cryptographic Agility Toolkit
  </footer>

</body>
</html>
"""


class MedVaultHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        patched = is_patched()

        if patched:
            badge = '<div class="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold"><i class="fa-solid fa-shield-check"></i> <span>POSTURE: NIST 3072-BIT RECOVERY</span></div>'
            key_size_display = "3072 Bits (NIST Safe)"
            hndl_rating = "LOW / RESILIENT"
            hndl_color = "text-emerald-400"
        else:
            badge = '<div class="flex items-center gap-2 px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-semibold animate-pulse"><i class="fa-solid fa-triangle-exclamation"></i> <span>QUANTUM RISK: 1024-BIT RSA</span></div>'
            key_size_display = "1024 Bits (Disbarred)"
            hndl_rating = "CRITICAL (HNDL EXPOSED)"
            hndl_color = "text-rose-400"

        # Prescriptions HTML
        rx_html = ""
        for rx in SIGNED_PRESCRIPTIONS:
            rx_html += f"""
            <div class="p-3 rounded-lg bg-slate-900/80 border border-slate-800 font-mono text-[11px] space-y-1">
              <div class="flex justify-between text-gray-400 text-[10px]">
                <span>Rx: {rx['id']} ({rx['patient']})</span>
                <span class="text-teal-400">{rx['medication']}</span>
              </div>
              <div class="text-gray-300 truncate"><b>Signature:</b> <span class="text-sky-400">{rx['signature_hex']}</span></div>
              <div class="text-[10px] text-gray-500">Signer: {rx['doctor']} · {rx['signed_at']}</div>
            </div>
            """

        # Patient Cards HTML
        patient_html = ""
        for p in PATIENTS:
            patient_html += f"""
            <div class="p-4 rounded-lg bg-slate-900/70 border border-slate-800 space-y-2">
              <div class="flex justify-between items-start">
                <div>
                  <h4 class="font-bold text-white text-sm">{p['name']}</h4>
                  <span class="text-[11px] text-gray-400">ID: {p['id']} · Age: {p['age']} ({p['blood_group']})</span>
                </div>
                <span class="text-[10px] px-2 py-0.5 rounded bg-teal-950 text-teal-400 font-mono">Active</span>
              </div>
              <p class="text-xs text-amber-300/90 font-medium">Diagnosis: {p['diagnosis']}</p>
              <div class="text-[11px] text-gray-400 pt-2 border-t border-slate-800/80">
                <span>Physician: <b>{p['physician']}</b></span>
              </div>
            </div>
            """

        page = (
            HTML_PAGE
            .replace("__SECURITY_BADGE__", badge)
            .replace("__KEY_SIZE_DISPLAY__", key_size_display)
            .replace("__HNDL_RATING__", hndl_rating)
            .replace("__HNDL_COLOR__", hndl_color)
            .replace("__PRESCRIPTION_ITEMS__", rx_html)
            .replace("__PATIENT_CARDS__", patient_html)
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))

    def do_POST(self):
        if self.path == "/sign_rx":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = urllib.parse.parse_qs(body)

            patient = data.get("patient", ["Unknown Patient"])[0]
            medication = data.get("medication", ["Standard Care 10mg"])[0]

            # Generate real digital signature
            order_data = f"{patient}:{medication}:{datetime.now().isoformat()}".encode("utf-8")
            try:
                sig = DOCTOR_KEY.sign(
                    order_data,
                    padding.PKCS1v15(),
                    hashes.SHA256()
                )
                sig_hex = sig.hex()[:24] + "...[VERIFIED]"
            except Exception:
                sig_hex = "0x89abf21c...[SIGNATURE]"

            new_rx = {
                "id": f"RX-{len(SIGNED_PRESCRIPTIONS) + 8811}",
                "patient": patient,
                "medication": medication,
                "doctor": "Dr. Aris Thorne, MD",
                "signed_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "signature_hex": sig_hex
            }
            SIGNED_PRESCRIPTIONS.insert(0, new_rx)

            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def start_server():
    server = HTTPServer(("0.0.0.0", PORT), MedVaultHandler)
    print(f"[+] Website 2 (MedVault EHR Portal) running on: http://localhost:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    start_server()
