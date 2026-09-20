"""Website 3: CipherCloud - Enterprise Encrypted File Vault & Secret Locker.

A dedicated, fully functional enterprise cloud storage & secret vault website.

FUNCTIONALITY:
- Enterprise Secret Document & API Key Locker.
- Interactive live file encryption & decryption in the browser.
- Real-time cryptographic integrity auditing & checksums.
- Stored payload inspector showing raw ciphertexts and authentication tags.

CRYPTOGRAPHIC VULNERABILITIES (BEFORE PATCH):
- Document storage encrypted using obsolete 56-bit DES symmetric cipher.
- Document integrity calculated using collision-weak MD5 hashes.

REMEDIATION (AFTER PATCH):
- Upgraded to FIPS 197 AES-256 block cipher and FIPS 180-4 SHA-256 integrity verification.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import hashlib
import json
import os
import sys
import urllib.parse
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PORT = 8083

# Mock File & Secret Storage
STORED_FILES = [
    {
        "id": "DOC-1092",
        "name": "Project_Chimera_Defence_Specs.pdf",
        "category": "Defense Blueprint",
        "size": "4.8 MB",
        "uploaded_at": "2026-09-19 09:40",
        "raw_secret": "CLASSIFIED-DEFENSE-PAYLOAD-CHIMERA-ORBITAL",
        "author": "Marcus Shaw (Director)"
    },
    {
        "id": "DOC-1091",
        "name": "Production_Postgres_Root_Key.env",
        "category": "Infrastructure Secret",
        "size": "240 Bytes",
        "uploaded_at": "2026-09-18 18:22",
        "raw_secret": "DB_PASSWORD=SuperSecretRootProd2026#Pass!",
        "author": "DevOps Automation Bot"
    },
    {
        "id": "DOC-1090",
        "name": "Quantum_Algorithm_IP_Valuation.xlsx",
        "category": "Intellectual Property",
        "size": "1.2 MB",
        "uploaded_at": "2026-09-17 14:15",
        "raw_secret": "PATENT_CLAIM_ID_US99410291_QKD_HYBRID",
        "author": "Dr. Elena Patel (Chief Scientist)"
    }
]

DES_KEY = b"VAULTKEY"  # 8 bytes = 56-bit effective DES
DES_IV = b"87654321"


def compute_file_checksum(data: str) -> str:
    """VULNERABILITY: Collision-weak MD5 hash for file integrity."""
    return hashlib.md5(data.encode("utf-8")).hexdigest()


def encrypt_document_content(content: str) -> str:
    """VULNERABILITY: 56-bit DES symmetric cipher."""
    try:
        cipher = Cipher(algorithms.DES(DES_KEY), modes.CBC(DES_IV))
        encryptor = cipher.encryptor()
        raw = content.encode("utf-8")
        pad_len = 8 - (len(raw) % 8)
        padded = raw + (bytes([pad_len]) * pad_len)
        return (encryptor.update(padded) + encryptor.finalize()).hex()
    except Exception:
        raw = content.encode("utf-8")
        return "".join(f"{b ^ 0xA5:02x}" for b in raw) + "e18f29d4"


def is_patched() -> bool:
    """Detects if ECDAT patch has been applied to this file."""
    with open(__file__, "r", encoding="utf-8") as f:
        src = f.read()
    return "return hashlib.sha256(" in src


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CipherCloud - Enterprise Encrypted Storage & Secret Vault</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0c0a17; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .glass-card { background: rgba(22, 18, 38, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(168, 85, 247, 0.18); }
    .glow-purple { box-shadow: 0 0 25px rgba(168, 85, 247, 0.12); }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- Header -->
  <header class="border-b border-purple-950 bg-purple-950/40 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="h-9 w-9 rounded-lg bg-gradient-to-tr from-purple-600 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg">
          <i class="fa-solid fa-cloud-arrow-up"></i>
        </div>
        <div>
          <span class="font-extrabold text-lg tracking-tight text-white">Cipher<span class="text-purple-400">Cloud</span></span>
          <span class="text-[10px] ml-2 px-2 py-0.5 rounded bg-purple-900/60 text-purple-300 font-mono">SECURE VAULT</span>
        </div>
      </div>

      <!-- Security Status Badge -->
      <div class="flex items-center gap-3">
        __SECURITY_BADGE__
        <div class="h-8 w-8 rounded-full bg-purple-950 border border-purple-700/50 flex items-center justify-center text-xs font-semibold text-purple-300">
          MS
        </div>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full space-y-8">

    <!-- Hero / Cloud Vault Storage Summary -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div class="glass-card rounded-xl p-6 glow-purple flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Encrypted Cloud Storage</span>
            <i class="fa-solid fa-hard-drive text-purple-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">1.48 TB Stored</div>
          <p class="text-xs text-purple-300 mt-1"><i class="fa-solid fa-lock"></i> 100% Encrypted at Rest & Transit</p>
        </div>
        <div class="mt-6 pt-4 border-t border-purple-950 flex items-center justify-between text-xs text-gray-400">
          <span>Replication: <b>Multi-Region S3</b></span>
          <span>Integrity: <b>Enabled</b></span>
        </div>
      </div>

      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Symmetric Encryption Cipher</span>
            <i class="fa-solid fa-key text-indigo-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">__CIPHER_NAME__</div>
          <p class="text-xs text-gray-400 mt-1">Checksum: __CHECKSUM_NAME__</p>
        </div>
        <div class="mt-6 pt-4 border-t border-purple-950 flex items-center justify-between text-xs text-gray-400">
          <span>Key Length: <b>__KEY_STRENGTH__</b></span>
          <span>Padding: <b>PKCS#7</b></span>
        </div>
      </div>

      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Security Officer</span>
            <i class="fa-solid fa-user-shield text-purple-400"></i>
          </div>
          <div class="text-lg font-bold text-white mt-3">Marcus Shaw</div>
          <div class="text-xs text-purple-300 mt-1">Director of Information Security · SecOps Admin</div>
        </div>
        <div class="mt-6 pt-4 border-t border-purple-950 flex items-center justify-between text-xs text-gray-400">
          <span>MFA Protection: <b>FIDO2 WebAuthn</b></span>
          <span>Access Level: <b>Top Secret</b></span>
        </div>
      </div>
    </div>

    <!-- Interactive Document Storage & Ciphertext Inspector -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
      
      <!-- Store Document Form -->
      <div class="glass-card rounded-xl p-6 space-y-6">
        <div class="border-b border-purple-950 pb-4">
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-file-shield text-purple-400"></i>
            Encrypt & Store Confidential Asset
          </h2>
          <p class="text-xs text-gray-400 mt-1">Submit confidential documents or credentials. Data is encrypted and checksummed live.</p>
        </div>

        <form action="/store" method="POST" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Document Name / File Identifier</label>
            <input type="text" name="name" required value="Strategic_Merger_Agreement_2026.docx" class="w-full bg-purple-950/40 border border-purple-800/60 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500 font-medium">
          </div>

          <div>
            <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Category / Classification</label>
            <select name="category" class="w-full bg-purple-950/40 border border-purple-800/60 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500">
              <option value="Mergers & Acquisitions">Mergers & Acquisitions (Restricted)</option>
              <option value="Executive Passwords">Executive Passwords / HSM Seed</option>
              <option value="Defense Blueprint">Defense / National Security</option>
            </select>
          </div>

          <div>
            <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Confidential Content / Secret Key</label>
            <textarea name="content" rows="2" required class="w-full bg-purple-950/40 border border-purple-800/60 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-purple-500 font-mono">VALUATION_ESTIMATE=$450_MILLION_TARGET_ACQUISITION</textarea>
          </div>

          <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-semibold py-2.5 rounded-lg shadow-lg flex items-center justify-center gap-2 text-sm transition-all">
            <i class="fa-solid fa-lock"></i>
            Encrypt & Commit to Vault
          </button>
        </form>
      </div>

      <!-- Ciphertext & Checksum Inspector -->
      <div class="glass-card rounded-xl p-6 space-y-6">
        <div class="border-b border-purple-950 pb-4 flex justify-between items-center">
          <div>
            <h2 class="text-lg font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-binary text-indigo-400"></i>
              Live Cryptographic Payload Inspector
            </h2>
            <p class="text-xs text-gray-400 mt-1">Real-time inspection of encrypted blocks stored in object storage</p>
          </div>
          <span class="text-xs px-2.5 py-1 rounded bg-purple-950 text-purple-400 border border-purple-800/50 font-mono">Live Vault</span>
        </div>

        <div class="space-y-3">
          __INSPECTOR_ITEMS__
        </div>

        <div class="p-3.5 rounded-lg bg-purple-950/40 border border-purple-900/60 text-xs space-y-1">
          <div class="font-semibold text-gray-300 flex items-center gap-1.5">
            <i class="fa-solid fa-shield-virus text-purple-400"></i>
            ECDAT Remediation Hook
          </div>
          <p class="text-gray-400 text-[11px]">
            Run <code class="text-purple-300 bg-purple-900/60 px-1 py-0.5 rounded">python -m backend patch --path demo_servers/website3_cipher_cloud --apply</code> to automatically upgrade this cloud vault to AES-256 & SHA-256.
          </p>
        </div>
      </div>

    </div>

    <!-- Stored Documents Table -->
    <div class="glass-card rounded-xl p-6 space-y-4">
      <div class="flex justify-between items-center">
        <h3 class="font-bold text-white text-base">Encrypted Document Catalog</h3>
        <span class="text-xs text-gray-400">Vault Access Log</span>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead>
            <tr class="border-b border-purple-950 text-gray-400 uppercase tracking-wider">
              <th class="py-3 px-4">Document ID</th>
              <th class="py-3 px-4">File Name</th>
              <th class="py-3 px-4">Category</th>
              <th class="py-3 px-4">Author</th>
              <th class="py-3 px-4">Timestamp</th>
              <th class="py-3 px-4 text-right">Integrity</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-purple-950/60 text-gray-300">
            __DOCUMENT_ROWS__
          </tbody>
        </table>
      </div>
    </div>

  </main>

  <!-- Footer -->
  <footer class="border-t border-purple-950 py-4 text-center text-xs text-gray-500 bg-purple-950/60">
    CipherCloud Enterprise Storage · Protected by ECDAT Cryptographic Agility Toolkit
  </footer>

</body>
</html>
"""


class CipherCloudHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        patched = is_patched()

        if patched:
            badge = '<div class="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold"><i class="fa-solid fa-shield-check"></i> <span>SECURITY: AES-256 & SHA-256 SECURED</span></div>'
            cipher_name = "AES-256 (FIPS 197)"
            checksum_name = "SHA-256 Checksum"
            key_strength = "256 Bits (Quantum Safe Margin)"
        else:
            badge = '<div class="flex items-center gap-2 px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-semibold animate-pulse"><i class="fa-solid fa-triangle-exclamation"></i> <span>VULNERABILITY: 56-BIT DES & MD5</span></div>'
            cipher_name = "DES-56 (Obsolete)"
            checksum_name = "MD5 Checksum (Weak)"
            key_strength = "56 Bits (Trivially Broken)"

        # Inspector HTML
        inspector_html = ""
        for doc in STORED_FILES[:3]:
            encrypted = encrypt_document_content(doc["raw_secret"])
            checksum = compute_file_checksum(doc["raw_secret"])
            inspector_html += f"""
            <div class="p-3 rounded-lg bg-purple-950/30 border border-purple-900/50 font-mono text-[11px] space-y-1">
              <div class="flex justify-between text-gray-400 text-[10px]">
                <span>{doc['name']}</span>
                <span class="text-purple-400">{cipher_name.split()[0]}</span>
              </div>
              <div class="text-gray-300 truncate"><b>Ciphertext:</b> <span class="text-purple-300">{encrypted}</span></div>
              <div class="text-gray-400 text-[10px] truncate">Checksum: {checksum}</div>
            </div>
            """

        # Table rows HTML
        table_html = ""
        for doc in STORED_FILES:
            table_html += f"""
            <tr class="hover:bg-purple-900/20">
              <td class="py-3 px-4 font-mono text-purple-400">{doc['id']}</td>
              <td class="py-3 px-4 font-medium text-white">{doc['name']}</td>
              <td class="py-3 px-4"><span class="px-2 py-0.5 rounded bg-purple-900/40 text-purple-300 text-[10px]">{doc['category']}</span></td>
              <td class="py-3 px-4 text-gray-400">{doc['author']}</td>
              <td class="py-3 px-4 text-gray-400">{doc['uploaded_at']}</td>
              <td class="py-3 px-4 text-right font-mono text-emerald-400"><i class="fa-solid fa-check-circle"></i> OK</td>
            </tr>
            """

        page = (
            HTML_PAGE
            .replace("__SECURITY_BADGE__", badge)
            .replace("__CIPHER_NAME__", cipher_name)
            .replace("__CHECKSUM_NAME__", checksum_name)
            .replace("__KEY_STRENGTH__", key_strength)
            .replace("__INSPECTOR_ITEMS__", inspector_html)
            .replace("__DOCUMENT_ROWS__", table_html)
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))

    def do_POST(self):
        if self.path == "/store":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = urllib.parse.parse_qs(body)

            name = data.get("name", ["Confidential_Doc.txt"])[0]
            category = data.get("category", ["General"])[0]
            content = data.get("content", ["Secret content"])[0]

            new_doc = {
                "id": f"DOC-{len(STORED_FILES) + 1093}",
                "name": name,
                "category": category,
                "size": f"{len(content.encode('utf-8'))} Bytes",
                "uploaded_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "raw_secret": content,
                "author": "Marcus Shaw (Admin)"
            }
            STORED_FILES.insert(0, new_doc)

            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


def start_server():
    server = HTTPServer(("0.0.0.0", PORT), CipherCloudHandler)
    print(f"[+] Website 3 (CipherCloud Vault) running on: http://localhost:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    start_server()
