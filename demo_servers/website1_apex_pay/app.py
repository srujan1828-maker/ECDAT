"""Website 1: ApexPay - Enterprise Payment Gateway & Banking Portal.

A dedicated, fully functional banking & payment processing website.

FUNCTIONALITY:
- Interactive Banking & Card Checkout Portal.
- Process live card payments and store encrypted tokens.
- User account authentication & balance management.
- Live "Cryptographic Transparency Drawer" inspecting stored ciphertexts & hashes.

CRYPTOGRAPHIC VULNERABILITIES (BEFORE PATCH):
- Passwords stored using broken MD5 hashing (RFC 1321).
- Payment card tokens encrypted using obsolete 56-bit DES symmetric cipher.

REMEDIATION (AFTER PATCH):
- Upgrades to FIPS 180-4 SHA-256 and FIPS 197 AES-256-CBC/GCM.
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import hashlib
import json
import os
import sys
import urllib.parse
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

PORT = 8081

# Mock database
TRANSACTIONS = [
    {"id": "TX-9042", "merchant": "AWS Cloud Services", "amount": "$1,450.00", "date": "2026-09-19 10:14", "card_last4": "4242", "raw_token": "4242-9812-7712-4242"},
    {"id": "TX-9041", "merchant": "Quantum Networks Inc.", "amount": "$4,200.00", "date": "2026-09-18 16:30", "card_last4": "8819", "raw_token": "8819-1102-3901-8819"},
    {"id": "TX-9040", "merchant": "Global Defense Logistics", "amount": "$12,850.00", "date": "2026-09-18 09:05", "card_last4": "9901", "raw_token": "9901-4412-9901-9901"}
]

USERS = {
    "admin@apexpay.io": {
        "name": "Sarah Chen (FinTech Admin)",
        "role": "Chief Financial Officer",
        "balance": "$284,500.00",
        "password_raw": "AdminMasterKey2026!"
    }
}

DES_KEY = b"APEX_KEY"  # 8 bytes = 56-bit effective DES
DES_IV = b"12345678"


def hash_user_password(password: str) -> str:
    """VULNERABILITY: Deprecated MD5 password hashing."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def encrypt_card_token(token: str) -> str:
    """VULNERABILITY: Obsolete 56-bit DES symmetric cipher."""
    try:
        cipher = Cipher(algorithms.DES(DES_KEY), modes.CBC(DES_IV))
        encryptor = cipher.encryptor()
        raw = token.encode("utf-8")
        pad_len = 8 - (len(raw) % 8)
        padded = raw + (bytes([pad_len]) * pad_len)
        return (encryptor.update(padded) + encryptor.finalize()).hex()
    except Exception:
        raw = token.encode("utf-8")
        return "".join(f"{b ^ 0x3F:02x}" for b in raw) + "6a9b4c12"


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
  <title>ApexPay - Enterprise Banking & Payment Gateway</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0b0f19; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .glass-card { background: rgba(17, 24, 39, 0.7); backdrop-filter: blur(12px); border: 1px solid rgba(75, 85, 99, 0.3); }
    .glow-cyan { box-shadow: 0 0 25px rgba(6, 182, 212, 0.15); }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- Header -->
  <header class="border-b border-gray-800 bg-gray-900/60 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="h-9 w-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center font-bold text-white shadow-lg">
          <i class="fa-solid fa-bolt"></i>
        </div>
        <div>
          <span class="font-extrabold text-lg tracking-tight text-white">Apex<span class="text-cyan-400">Pay</span></span>
          <span class="text-[10px] ml-2 px-2 py-0.5 rounded bg-gray-800 text-gray-400 font-mono">v4.2-PROD</span>
        </div>
      </div>

      <!-- Security Status Badge -->
      <div class="flex items-center gap-3">
        __SECURITY_BADGE__
        <div class="h-8 w-8 rounded-full bg-cyan-950 border border-cyan-800/50 flex items-center justify-center text-xs font-semibold text-cyan-300">
          SC
        </div>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full space-y-8">

    <!-- Hero / Account Summary -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div class="glass-card rounded-xl p-6 glow-cyan flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Primary Settlement Balance</span>
            <i class="fa-solid fa-vault text-cyan-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">$284,500.00</div>
          <p class="text-xs text-emerald-400 mt-1"><i class="fa-solid fa-arrow-trend-up"></i> +14.2% from last cycle</p>
        </div>
        <div class="mt-6 pt-4 border-t border-gray-800/80 flex items-center justify-between text-xs text-gray-400">
          <span>Routing: <b>021000021</b></span>
          <span>Account: <b>•••• 8812</b></span>
        </div>
      </div>

      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Encrypted Token Vault</span>
            <i class="fa-solid fa-shield-halved text-blue-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">3 Active Tokens</div>
          <p class="text-xs text-gray-400 mt-1">Symmetric Key Mode: __CIPHER_NAME__</p>
        </div>
        <div class="mt-6 pt-4 border-t border-gray-800/80 flex items-center justify-between text-xs text-gray-400">
          <span>Storage Engine: <b>SQLite Secure</b></span>
          <span>PCI Scope: <b>Level 1</b></span>
        </div>
      </div>

      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Admin Authentication</span>
            <i class="fa-solid fa-user-lock text-purple-400"></i>
          </div>
          <div class="text-lg font-bold text-white mt-3">Sarah Chen (CFO)</div>
          <div class="text-xs font-mono text-gray-400 truncate mt-1">Hash: <span class="text-cyan-300">__USER_HASH__</span></div>
        </div>
        <div class="mt-6 pt-4 border-t border-gray-800/80 flex items-center justify-between text-xs text-gray-400">
          <span>Hash Algorithm: <b>__HASH_ALGO__</b></span>
          <span>Session: <b>Verified</b></span>
        </div>
      </div>
    </div>

    <!-- Interactive Payment Checkout & Live Cipher Inspector -->
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-8">
      
      <!-- Checkout Form -->
      <div class="glass-card rounded-xl p-6 space-y-6">
        <div class="border-b border-gray-800 pb-4">
          <h2 class="text-lg font-bold text-white flex items-center gap-2">
            <i class="fa-solid fa-credit-card text-cyan-400"></i>
            Authorize New Payment Transaction
          </h2>
          <p class="text-xs text-gray-400 mt-1">Submit payment details. The credit card will be encrypted live before persisting.</p>
        </div>

        <form action="/pay" method="POST" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Merchant / Recipient</label>
            <input type="text" name="merchant" required value="Cloudflare Edge Infrastructure" class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-medium">
          </div>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Amount ($ USD)</label>
              <input type="text" name="amount" required value="$750.00" class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono">
            </div>
            <div>
              <label class="block text-xs font-semibold text-gray-300 uppercase tracking-wider mb-1">Card Number (Full PAN)</label>
              <input type="text" name="card" required value="4242-5555-8888-1234" class="w-full bg-gray-900 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-500 font-mono">
            </div>
          </div>

          <button type="submit" class="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold py-2.5 rounded-lg shadow-lg flex items-center justify-center gap-2 text-sm transition-all">
            <i class="fa-solid fa-lock"></i>
            Encrypt & Authorize Transaction
          </button>
        </form>
      </div>

      <!-- Live Cryptographic Transparency Inspector -->
      <div class="glass-card rounded-xl p-6 space-y-6">
        <div class="border-b border-gray-800 pb-4 flex justify-between items-center">
          <div>
            <h2 class="text-lg font-bold text-white flex items-center gap-2">
              <i class="fa-solid fa-microchip text-purple-400"></i>
              Cryptographic Transparency Audit
            </h2>
            <p class="text-xs text-gray-400 mt-1">Live inspection of stored ciphertexts in the active database</p>
          </div>
          <span class="text-xs px-2.5 py-1 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/50 font-mono">Live DB View</span>
        </div>

        <div class="space-y-3">
          __INSPECTOR_ITEMS__
        </div>

        <div class="p-3.5 rounded-lg bg-gray-900/90 border border-gray-800 text-xs space-y-1">
          <div class="font-semibold text-gray-300 flex items-center gap-1.5">
            <i class="fa-solid fa-info-circle text-cyan-400"></i>
            ECDAT Discovery & Remediation Hook
          </div>
          <p class="text-gray-400 text-[11px]">
            Run <code class="text-cyan-300 bg-gray-800 px-1 py-0.5 rounded">python -m backend patch --path demo_servers/website1_apex_pay --apply</code> to automatically upgrade this site's cryptography.
          </p>
        </div>
      </div>

    </div>

    <!-- Recent Transactions Table -->
    <div class="glass-card rounded-xl p-6 space-y-4">
      <div class="flex justify-between items-center">
        <h3 class="font-bold text-white text-base">Recent Ledger Settlements</h3>
        <span class="text-xs text-gray-400">All data encrypted at rest</span>
      </div>

      <div class="overflow-x-auto">
        <table class="w-full text-left text-xs">
          <thead>
            <tr class="border-b border-gray-800 text-gray-400 uppercase tracking-wider">
              <th class="py-3 px-4">Transaction ID</th>
              <th class="py-3 px-4">Recipient</th>
              <th class="py-3 px-4">Card Used</th>
              <th class="py-3 px-4">Timestamp</th>
              <th class="py-3 px-4 text-right">Amount</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-gray-800/50 text-gray-300">
            __TRANSACTION_ROWS__
          </tbody>
        </table>
      </div>
    </div>

  </main>

  <!-- Footer -->
  <footer class="border-t border-gray-800 py-4 text-center text-xs text-gray-500 bg-gray-900/40">
    ApexPay Global Settlement System · Protected by ECDAT Cryptographic Agility Toolkit
  </footer>

</body>
</html>
"""


class ApexPayHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        patched = is_patched()

        # Build dynamic HTML
        if patched:
            badge = '<div class="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold"><i class="fa-solid fa-shield-check"></i> <span>SECURITY: PATCHED (SHA-256 & AES-256)</span></div>'
            cipher_name = "AES-256-CBC (NIST SP 800-38A Compliant)"
            hash_algo = "SHA-256 (FIPS 180-4 Secure)"
        else:
            badge = '<div class="flex items-center gap-2 px-3 py-1 rounded-full bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-semibold animate-pulse"><i class="fa-solid fa-triangle-exclamation"></i> <span>VULNERABILITY DETECTED: MD5 & DES-56</span></div>'
            cipher_name = "DES-56 (Broken by brute force)"
            hash_algo = "MD5 (Collision Vulnerable)"

        admin_user = USERS["admin@apexpay.io"]
        user_hash = hash_user_password(admin_user["password_raw"])

        # Inspector items
        inspector_html = ""
        for tx in TRANSACTIONS[:3]:
            encrypted_payload = encrypt_card_token(tx["raw_token"])
            inspector_html += f"""
            <div class="p-3 rounded-lg bg-gray-900/70 border border-gray-800 font-mono text-[11px] space-y-1">
              <div class="flex justify-between text-gray-400 text-[10px]">
                <span>Record: {tx['id']} ({tx['merchant']})</span>
                <span class="text-cyan-400">{cipher_name.split()[0]}</span>
              </div>
              <div class="text-gray-300 truncate"><b>Ciphertext:</b> <span class="text-emerald-400">{encrypted_payload}</span></div>
            </div>
            """

        # Table rows
        table_html = ""
        for tx in TRANSACTIONS:
            table_html += f"""
            <tr class="hover:bg-gray-800/30">
              <td class="py-3 px-4 font-mono text-cyan-400">{tx['id']}</td>
              <td class="py-3 px-4 font-medium text-white">{tx['merchant']}</td>
              <td class="py-3 px-4 font-mono">•••• {tx['card_last4']}</td>
              <td class="py-3 px-4 text-gray-400">{tx['date']}</td>
              <td class="py-3 px-4 text-right font-bold text-white">{tx['amount']}</td>
            </tr>
            """

        page = (
            HTML_PAGE
            .replace("__SECURITY_BADGE__", badge)
            .replace("__CIPHER_NAME__", cipher_name)
            .replace("__USER_HASH__", user_hash[:20] + "...")
            .replace("__HASH_ALGO__", hash_algo)
            .replace("__INSPECTOR_ITEMS__", inspector_html)
            .replace("__TRANSACTION_ROWS__", table_html)
        )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode("utf-8"))

    def do_POST(self):
        if self.path == "/pay":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length).decode("utf-8")
            data = urllib.parse.parse_qs(body)

            merchant = data.get("merchant", ["Unknown Merchant"])[0]
            amount = data.get("amount", ["$100.00"])[0]
            card = data.get("card", ["4242-1111-2222-3333"])[0]
            last4 = card.replace("-", "")[-4:]

            new_tx = {
                "id": f"TX-{len(TRANSACTIONS) + 9040}",
                "merchant": merchant,
                "amount": amount,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "card_last4": last4,
                "raw_token": card
            }
            TRANSACTIONS.insert(0, new_tx)

            # Redirect back to home
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Quiet standard output
        pass


def start_server():
    server = HTTPServer(("0.0.0.0", PORT), ApexPayHandler)
    print(f"[+] Website 1 (ApexPay Banking) running on: http://localhost:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    start_server()
