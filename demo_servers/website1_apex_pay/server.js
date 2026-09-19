/**
 * Website 1: ApexPay - Enterprise Banking & Payment Gateway (Node.js)
 * 
 * Fully functional Node.js FinTech Banking & Card Checkout Portal.
 * 
 * CRYPTOGRAPHIC VULNERABILITIES (BEFORE PATCH):
 * - Passwords & integrity hashes computed using broken MD5 (RFC 1321).
 * - Payment card tokens encrypted using obsolete 56-bit DES symmetric cipher.
 * 
 * REMEDIATION (AFTER PATCH):
 * - Upgrades to FIPS 180-4 SHA-256 and FIPS 197 AES-256-CBC.
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 8081;

// Mock database
let TRANSACTIONS = [
  { id: 'TX-9042', merchant: 'AWS Cloud Services', amount: '$1,450.00', date: '2026-09-19 10:14', card_last4: '4242', raw_token: '4242-9812-7712-4242', encrypted_token: '', hash: '' },
  { id: 'TX-9041', merchant: 'Quantum Networks Inc.', amount: '$4,200.00', date: '2026-09-18 16:30', card_last4: '8819', raw_token: '8819-1102-3901-8819', encrypted_token: '', hash: '' },
  { id: 'TX-9040', merchant: 'Global Defense Logistics', amount: '$12,850.00', date: '2026-09-18 09:05', card_last4: '9901', raw_token: '9901-4412-9901-9901', encrypted_token: '', hash: '' }
];

const USER = {
  name: 'Sarah Chen (FinTech Admin)',
  email: 'admin@apexpay.io',
  role: 'Chief Financial Officer',
  balance: '$284,500.00',
  password_raw: 'AdminMasterKey2026!'
};

// Check if source code has been patched by ECDAT
function isPatched() {
  try {
    const src = fs.readFileSync(__filename, 'utf8');
    const targetSig = 'createHash(' + "'sha256')";
    return src.includes(targetSig);
  } catch (e) {
    return false;
  }
}

// Password hashing function (VULNERABLE: MD5)
function hashUserPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Card token symmetric encryption (VULNERABLE: 56-bit DES)
function encryptCardToken(token) {
  try {
    if (isPatched()) {
      const key = crypto.createHash('sha' + '256').update('APEX_ENTERPRISE_KEY_2026').digest();
      const iv = Buffer.from('1234567812345678', 'utf8');
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      let encrypted = cipher.update(token, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return encrypted;
    }
    const key = Buffer.alloc(8, 'APEX_KEY');
    const iv = Buffer.alloc(8, '12345678');
    const cipher = crypto.createCipheriv('des-cbc', key, iv);
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch (err) {
    // Fallback if OpenSSL 3 denies legacy DES
    return Buffer.from(token).toString('hex') + 'deadbeef56bit';
  }
}

// Initialize mock ciphertexts
function refreshMockEncryptions() {
  for (const tx of TRANSACTIONS) {
    if (!tx.encrypted_token) {
      tx.encrypted_token = encryptCardToken(tx.raw_token);
      tx.hash = hashUserPassword(tx.id + tx.amount);
    }
  }
}
refreshMockEncryptions();

function renderPage() {
  const patched = isPatched();
  const hashAlgo = patched ? 'SHA-256' : 'MD5';
  const hashStandard = patched ? 'FIPS 180-4 Compliant (256-bit)' : 'RFC 1321 (128-bit Broken)';
  const cipherAlgo = patched ? 'AES-256-CBC' : 'DES-CBC';
  const cipherStandard = patched ? 'FIPS 197 Standard (256-bit Key)' : 'FIPS 46-3 Deprecated (56-bit Key)';
  const adminPasswordHash = hashUserPassword(USER.password_raw);

  const securityBadge = patched
    ? `<div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 text-xs font-semibold shadow-lg shadow-emerald-950/40">
         <i class="fa-solid fa-circle-check"></i>
         <span>SECURITY PATCHED: SHA-256 & AES-256</span>
       </div>`
    : `<div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/40 text-rose-400 text-xs font-semibold animate-pulse shadow-lg shadow-rose-950/40">
         <i class="fa-solid fa-triangle-exclamation"></i>
         <span>VULNERABLE: MD5 & 56-bit DES CIPHER</span>
       </div>`;

  const rows = TRANSACTIONS.map(tx => {
    const enc = encryptCardToken(tx.raw_token);
    const h = hashUserPassword(tx.id + tx.amount);
    return `
      <tr class="border-b border-gray-800/60 hover:bg-gray-800/30 text-xs transition-colors">
        <td class="py-3 px-4 font-mono font-bold text-cyan-400">${tx.id}</td>
        <td class="py-3 px-4 font-medium text-white">${tx.merchant}</td>
        <td class="py-3 px-4 font-bold text-gray-200">${tx.amount}</td>
        <td class="py-3 px-4 font-mono text-gray-400">•••• ${tx.card_last4}</td>
        <td class="py-3 px-4 font-mono text-gray-400 text-[11px] max-w-[200px] truncate" title="${enc}">
          ${enc}
        </td>
        <td class="py-3 px-4 text-right">
          <button onclick="inspectTx('${tx.id}', '${tx.merchant}', '${tx.amount}', '${enc}', '${h}')" class="px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-cyan-300 text-[11px] font-medium border border-gray-700">
            <i class="fa-solid fa-fingerprint mr-1"></i> Inspect
          </button>
        </td>
      </tr>
    `;
  }).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ApexPay - Enterprise Banking & Payment Gateway (Node.js)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0b0f19; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .glass-card { background: rgba(17, 24, 39, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(75, 85, 99, 0.3); }
    .glow-cyan { box-shadow: 0 0 25px rgba(6, 182, 212, 0.15); }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- Header -->
  <header class="border-b border-gray-800 bg-gray-900/70 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="h-9 w-9 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-600 flex items-center justify-center font-bold text-white shadow-lg">
          <i class="fa-solid fa-bolt"></i>
        </div>
        <div>
          <span class="font-extrabold text-lg tracking-tight text-white">Apex<span class="text-cyan-400">Pay</span></span>
          <span class="text-[10px] ml-2 px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 font-mono border border-cyan-800/40">Node.js Engine</span>
        </div>
      </div>

      <!-- Security Status Badge -->
      <div class="flex items-center gap-3">
        ${securityBadge}
        <button onclick="location.reload()" class="h-8 w-8 rounded-lg bg-gray-800 hover:bg-gray-700 border border-gray-700 flex items-center justify-center text-xs text-gray-300" title="Refresh Live State">
          <i class="fa-solid fa-rotate"></i>
        </button>
      </div>
    </div>
  </header>

  <!-- Main Container -->
  <main class="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full space-y-8">

    <!-- Top Account Cards -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      
      <!-- Card 1: Balance -->
      <div class="glass-card rounded-xl p-6 glow-cyan flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Primary Settlement Balance</span>
            <i class="fa-solid fa-vault text-cyan-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">${USER.balance}</div>
          <p class="text-xs text-emerald-400 mt-1"><i class="fa-solid fa-arrow-trend-up"></i> Live FinTech Gateway Active</p>
        </div>
        <div class="mt-6 pt-4 border-t border-gray-800/80 flex items-center justify-between text-xs text-gray-400 font-mono">
          <span>Routing: <b>021000021</b></span>
          <span>Account: <b>•••• 8812</b></span>
        </div>
      </div>

      <!-- Card 2: Cryptographic Posture -->
      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Cryptographic Primitives</span>
            <i class="fa-solid fa-shield-halved ${patched ? 'text-emerald-400' : 'text-rose-400'}"></i>
          </div>
          <div class="mt-3 space-y-2">
            <div class="flex justify-between text-xs">
              <span class="text-gray-400">Password Hasher:</span>
              <span class="font-mono font-bold ${patched ? 'text-emerald-400' : 'text-rose-400'}">${hashAlgo}</span>
            </div>
            <div class="flex justify-between text-xs">
              <span class="text-gray-400">Token Cipher:</span>
              <span class="font-mono font-bold ${patched ? 'text-emerald-400' : 'text-rose-400'}">${cipherAlgo}</span>
            </div>
          </div>
        </div>
        <div class="mt-4 pt-3 border-t border-gray-800/80 text-[11px] text-gray-400">
          Standard: <span class="${patched ? 'text-emerald-300' : 'text-rose-300'} font-medium">${cipherStandard}</span>
        </div>
      </div>

      <!-- Card 3: Compliance Gauge -->
      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>PCI-DSS & FIPS Audit</span>
            <i class="fa-solid fa-certificate ${patched ? 'text-emerald-400' : 'text-amber-400'}"></i>
          </div>
          <div class="mt-3">
            <div class="text-2xl font-black ${patched ? 'text-emerald-400' : 'text-rose-400'}">
              ${patched ? '100% PASS' : 'CRITICAL FAIL'}
            </div>
            <p class="text-xs text-gray-400 mt-1">
              ${patched ? 'PCI-DSS v4.0 & FIPS 140-3 Compliant' : 'Violation: Obsolete 56-bit DES & MD5'}
            </p>
          </div>
        </div>
        <div class="mt-4 pt-3 border-t border-gray-800/80 flex items-center justify-between text-xs">
          <span class="text-gray-400">ECDAT Agility Status:</span>
          <span class="font-semibold ${patched ? 'text-emerald-400' : 'text-amber-400'}">
            ${patched ? 'Patched in Code' : 'Vulnerable Target'}
          </span>
        </div>
      </div>
    </div>

    <!-- Interactive Grid: Checkout Form & Transactions Ledger -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">

      <!-- Payment Checkout Form -->
      <div class="glass-card rounded-xl p-6 space-y-5">
        <div class="border-b border-gray-800 pb-3">
          <h3 class="font-bold text-white text-base flex items-center gap-2">
            <i class="fa-solid fa-credit-card text-cyan-400"></i>
            <span>Process Payment & Tokenize</span>
          </h3>
          <p class="text-xs text-gray-400 mt-1">
            Simulate a real checkout transaction. Token will be encrypted via <b class="${patched ? 'text-emerald-400' : 'text-rose-400'} font-mono">${cipherAlgo}</b>.
          </p>
        </div>

        <form action="/process-payment" method="POST" class="space-y-4">
          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Merchant / Vendor</label>
            <input type="text" name="merchant" value="Stripe API Gateway" required class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-medium">
          </div>

          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Cardholder Name</label>
            <input type="text" name="cardholder" value="Dr. A. Sharma" required class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-medium">
          </div>

          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Credit Card Number</label>
            <input type="text" name="card_number" value="4532 9812 7701 4242" required class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono">
          </div>

          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="block text-xs text-gray-400 font-medium mb-1">Amount ($ USD)</label>
              <input type="text" name="amount" value="$850.00" required class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-bold">
            </div>
            <div>
              <label class="block text-xs text-gray-400 font-medium mb-1">CVV Security Code</label>
              <input type="password" name="cvv" value="892" required class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500 font-mono">
            </div>
          </div>

          <button type="submit" class="w-full py-2.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-bold text-xs shadow-lg shadow-cyan-950/40 flex items-center justify-center gap-2 transition-all">
            <i class="fa-solid fa-lock"></i>
            <span>Authorize & Encrypt Card Token</span>
          </button>
        </form>
      </div>

      <!-- Transactions Ledger -->
      <div class="glass-card rounded-xl p-6 space-y-4 lg:col-span-2">
        <div class="flex items-center justify-between border-b border-gray-800 pb-3">
          <div>
            <h3 class="font-bold text-white text-base flex items-center gap-2">
              <i class="fa-solid fa-receipt text-cyan-400"></i>
              <span>Live Settlement Ledger</span>
            </h3>
            <p class="text-xs text-gray-400 mt-0.5">Encrypted card tokens stored in enterprise vault.</p>
          </div>
          <span class="text-[11px] px-2.5 py-1 rounded bg-gray-800 text-gray-300 font-mono">
            ${TRANSACTIONS.length} Records
          </span>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead>
              <tr class="border-b border-gray-800 text-gray-400 text-[11px] uppercase tracking-wider font-semibold">
                <th class="py-2 px-4">TX ID</th>
                <th class="py-2 px-4">Merchant</th>
                <th class="py-2 px-4">Amount</th>
                <th class="py-2 px-4">Card</th>
                <th class="py-2 px-4">Ciphertext (${cipherAlgo})</th>
                <th class="py-2 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              ${rows}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Cryptographic Transparency Drawer -->
    <div class="glass-card rounded-xl p-6 border-cyan-900/40 glow-cyan space-y-4">
      <div class="flex items-center justify-between border-b border-gray-800 pb-3">
        <div class="flex items-center gap-2">
          <i class="fa-solid fa-magnifying-glass-chart text-cyan-400"></i>
          <h3 class="font-bold text-white text-sm">Cryptographic Inspector (Live Node.js Runtime)</h3>
        </div>
        <span class="text-xs text-gray-400 font-mono">Process PID: ${process.pid}</span>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
        <div class="p-3.5 rounded-lg bg-gray-900/80 border border-gray-800 space-y-1.5">
          <div class="text-gray-400 font-semibold flex items-center justify-between">
            <span>Admin Password Storage Hash</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono ${patched ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'}">${hashAlgo}</span>
          </div>
          <div class="font-mono text-gray-300 text-[11px] break-all bg-gray-950 p-2 rounded border border-gray-800/80">
            ${adminPasswordHash}
          </div>
          <div class="text-[10px] ${patched ? 'text-emerald-400' : 'text-rose-400'}">
            ${patched ? '✓ FIPS 180-4 SHA-256 (Pre-image resistant, collision resistant)' : '✗ Vulnerable to instant rainbow table and MD5 collision attacks!'}
          </div>
        </div>

        <div class="p-3.5 rounded-lg bg-gray-900/80 border border-gray-800 space-y-1.5">
          <div class="text-gray-400 font-semibold flex items-center justify-between">
            <span>Active Card Vault Symmetric Cipher</span>
            <span class="px-2 py-0.5 rounded text-[10px] font-mono ${patched ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' : 'bg-rose-950 text-rose-300 border border-rose-800'}">${cipherAlgo}</span>
          </div>
          <div class="font-mono text-gray-300 text-[11px] break-all bg-gray-950 p-2 rounded border border-gray-800/80">
            ${encryptCardToken('SAMPLE-CARD-4242')}
          </div>
          <div class="text-[10px] ${patched ? 'text-emerald-400' : 'text-rose-400'}">
            ${patched ? '✓ AES-256 with 256-bit symmetric security margin (Quantum Grover resistant)' : '✗ 56-bit DES cracked in < 24 hours via brute-force!'}
          </div>
        </div>
      </div>
    </div>
  </main>

  <!-- Modal for Inspect -->
  <div id="inspectModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
    <div class="glass-card max-w-lg w-full rounded-xl p-6 space-y-4 border-cyan-800/60 shadow-2xl">
      <div class="flex items-center justify-between border-b border-gray-800 pb-3">
        <h4 class="font-bold text-white text-sm flex items-center gap-2">
          <i class="fa-solid fa-fingerprint text-cyan-400"></i>
          <span>Transaction Cryptography Inspector</span>
        </h4>
        <button onclick="closeModal()" class="text-gray-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="space-y-3 text-xs">
        <div>
          <span class="text-gray-400 block mb-1">Transaction ID & Merchant:</span>
          <div id="modalTxMeta" class="font-semibold text-white"></div>
        </div>
        <div>
          <span class="text-gray-400 block mb-1">Ciphertext Token (${cipherAlgo}):</span>
          <div id="modalCiphertext" class="p-2.5 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-cyan-300 break-all"></div>
        </div>
        <div>
          <span class="text-gray-400 block mb-1">Integrity Signature Hash (${hashAlgo}):</span>
          <div id="modalHash" class="p-2.5 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-purple-300 break-all"></div>
        </div>
      </div>
      <div class="pt-3 border-t border-gray-800 text-right">
        <button onclick="closeModal()" class="px-4 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-white text-xs font-semibold">
          Close Inspector
        </button>
      </div>
    </div>
  </div>

  <script>
    function inspectTx(id, merchant, amount, enc, h) {
      document.getElementById('modalTxMeta').textContent = id + ' — ' + merchant + ' (' + amount + ')';
      document.getElementById('modalCiphertext').textContent = enc;
      document.getElementById('modalHash').textContent = h;
      document.getElementById('inspectModal').classList.remove('hidden');
    }
    function closeModal() {
      document.getElementById('inspectModal').classList.add('hidden');
    }
  </script>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);

  if (req.method === 'GET' && parsed.pathname === '/') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(renderPage());
    return;
  }

  if (req.method === 'GET' && parsed.pathname === '/api/state') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      patched: isPatched(),
      hash_algorithm: isPatched() ? 'SHA-256' : 'MD5',
      cipher_algorithm: isPatched() ? 'AES-256-CBC' : 'DES-CBC',
      transactions_count: TRANSACTIONS.length
    }));
    return;
  }

  if (req.method === 'POST' && parsed.pathname === '/process-payment') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const merchant = params.get('merchant') || 'Online Merchant';
      const amount = params.get('amount') || '$100.00';
      const cardNumber = params.get('card_number') || '4111 2222 3333 4444';
      const last4 = cardNumber.replace(/\s+/g, '').slice(-4) || '4242';
      const txId = 'TX-' + Math.floor(1000 + Math.random() * 9000);

      const enc = encryptCardToken(cardNumber);
      const h = hashUserPassword(txId + amount);

      TRANSACTIONS.unshift({
        id: txId,
        merchant: merchant,
        amount: amount,
        date: new Date().toISOString().replace('T', ' ').slice(0, 16),
        card_last4: last4,
        raw_token: cardNumber,
        encrypted_token: enc,
        hash: h
      });

      res.writeHead(302, { 'Location': '/' });
      res.end();
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[ApexPay Node.js] Server listening on http://0.0.0.0:${PORT} (http://localhost:${PORT})`);
});
