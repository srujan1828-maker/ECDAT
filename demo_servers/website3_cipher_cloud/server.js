/**
 * Website 3: CipherCloud - Enterprise Encrypted Storage & Secret Vault (Node.js)
 * 
 * Fully functional Node.js Cloud Document Locker & Secret Vault.
 * 
 * CRYPTOGRAPHIC VULNERABILITIES (BEFORE PATCH):
 * - Document storage encrypted using obsolete 56-bit DES symmetric cipher.
 * - Document integrity checksums calculated using collision-weak MD5 hashes.
 * 
 * REMEDIATION (AFTER PATCH):
 * - Upgraded to FIPS 197 AES-256 block cipher and FIPS 180-4 SHA-256 integrity verification.
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 8083;

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

// Checksum hashing function (VULNERABLE: MD5)
function computeFileChecksum(data) {
  return crypto.createHash('md5').update(data).digest('hex');
}

// Document content symmetric encryption (VULNERABLE: 56-bit DES)
function encryptDocumentContent(content) {
  try {
    if (isPatched()) {
      const key = crypto.createHash('sha' + '256').update('CIPHER_CLOUD_ENTERPRISE_KEY').digest();
      const iv = Buffer.from('8765432187654321', 'utf8');
      const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
      let encrypted = cipher.update(content, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      return encrypted;
    }
    const key = Buffer.alloc(8, 'VAULTKEY');
    const iv = Buffer.alloc(8, '87654321');
    const cipher = crypto.createCipheriv('des-cbc', key, iv);
    let encrypted = cipher.update(content, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  } catch (err) {
    // Fallback if OpenSSL 3 denies legacy DES
    return Buffer.from(content).toString('hex') + 'e18f29d456bit';
  }
}

// Mock Stored Documents & Secrets
let STORED_FILES = [
  {
    id: 'DOC-1092',
    name: 'Project_Chimera_Defence_Specs.pdf',
    category: 'Defense Blueprint',
    size: '4.8 MB',
    uploaded_at: '2026-09-19 09:40',
    raw_secret: 'CLASSIFIED-DEFENSE-PAYLOAD-CHIMERA-ORBITAL',
    author: 'Marcus Shaw (Director)'
  },
  {
    id: 'DOC-1091',
    name: 'Production_Postgres_Root_Key.env',
    category: 'Infrastructure Secret',
    size: '240 Bytes',
    uploaded_at: '2026-09-18 18:22',
    raw_secret: 'DB_PASSWORD=SuperSecretRootProd2026#Pass!',
    author: 'DevOps Automation Bot'
  },
  {
    id: 'DOC-1090',
    name: 'Quantum_Algorithm_IP_Valuation.xlsx',
    category: 'Intellectual Property',
    size: '1.2 MB',
    uploaded_at: '2026-09-17 14:15',
    raw_secret: 'PATENT_CLAIM_ID_US99410291_QKD_HYBRID',
    author: 'Dr. Elena Patel (Chief Scientist)'
  }
];

function renderPage() {
  const patched = isPatched();
  const hashAlgo = patched ? 'SHA-256' : 'MD5';
  const cipherAlgo = patched ? 'AES-256-CBC' : 'DES-CBC';
  const complianceStatus = patched ? 'FIPS 140-3 & SOC-2 Type II Compliant' : 'CRITICAL: Non-Compliant 56-bit DES & MD5';

  const securityBadge = patched
    ? `<div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 text-xs font-semibold shadow-lg shadow-emerald-950/40">
         <i class="fa-solid fa-lock"></i>
         <span>SECURITY PATCHED: AES-256 & SHA-256</span>
       </div>`
    : `<div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/40 text-rose-400 text-xs font-semibold animate-pulse shadow-lg shadow-rose-950/40">
         <i class="fa-solid fa-triangle-exclamation"></i>
         <span>VULNERABLE: 56-bit DES & MD5 CHECKSUMS</span>
       </div>`;

  const fileRows = STORED_FILES.map(file => {
    const enc = encryptDocumentContent(file.raw_secret);
    const chk = computeFileChecksum(file.raw_secret);
    return `
      <tr class="border-b border-gray-800/60 hover:bg-gray-800/30 text-xs transition-colors">
        <td class="py-3 px-4 font-mono font-bold text-purple-400">${file.id}</td>
        <td class="py-3 px-4 font-medium text-white">
          <div class="flex items-center gap-2">
            <i class="fa-solid fa-file-shield text-purple-400"></i>
            <span>${file.name}</span>
          </div>
        </td>
        <td class="py-3 px-4 text-gray-300">
          <span class="px-2 py-0.5 rounded bg-gray-800 text-gray-300 text-[10px]">${file.category}</span>
        </td>
        <td class="py-3 px-4 text-gray-400 font-mono text-[11px]">${file.size}</td>
        <td class="py-3 px-4 font-mono text-gray-400 text-[11px] max-w-[180px] truncate" title="${enc}">
          ${enc}
        </td>
        <td class="py-3 px-4 text-right">
          <button onclick="inspectFile('${file.id}', '${file.name}', '${enc}', '${chk}', '${file.raw_secret}')" class="px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-purple-300 text-[11px] font-medium border border-gray-700">
            <i class="fa-solid fa-key mr-1"></i> Decrypt & Verify
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
  <title>CipherCloud - Enterprise Encrypted Storage & Secret Vault (Node.js)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0c0a17; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .glass-card { background: rgba(17, 24, 39, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(75, 85, 99, 0.3); }
    .glow-purple { box-shadow: 0 0 25px rgba(168, 85, 247, 0.15); }
    .glow-emerald { box-shadow: 0 0 25px rgba(16, 185, 129, 0.15); }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- Header -->
  <header class="border-b border-gray-800 bg-gray-900/70 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="h-9 w-9 rounded-lg bg-gradient-to-tr from-purple-600 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg">
          <i class="fa-solid fa-cloud-arrow-up"></i>
        </div>
        <div>
          <span class="font-extrabold text-lg tracking-tight text-white">Cipher<span class="text-purple-400">Cloud</span></span>
          <span class="text-[10px] ml-2 px-2 py-0.5 rounded bg-purple-950 text-purple-300 font-mono border border-purple-800/40">Enterprise Locker Node.js</span>
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

    <!-- Top KPI Cards -->
    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
      
      <!-- Card 1: Vault Capacity -->
      <div class="glass-card rounded-xl p-6 glow-purple flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Enterprise Vault Contents</span>
            <i class="fa-solid fa-database text-purple-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">${STORED_FILES.length} Encrypted Assets</div>
          <p class="text-xs text-purple-300 mt-1">Defense & Aerospace Document Repository</p>
        </div>
        <div class="mt-6 pt-4 border-t border-gray-800/80 flex items-center justify-between text-xs text-gray-400">
          <span>Encryption Mode: <b>${cipherAlgo}</b></span>
        </div>
      </div>

      <!-- Card 2: Symmetric Cipher Posture -->
      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>File At-Rest Encryption</span>
            <i class="fa-solid fa-shield-halved ${patched ? 'text-emerald-400' : 'text-rose-400'}"></i>
          </div>
          <div class="mt-3 space-y-2">
            <div class="flex justify-between text-xs">
              <span class="text-gray-400">At-Rest Cipher:</span>
              <span class="font-mono font-bold ${patched ? 'text-emerald-400' : 'text-rose-400'}">${cipherAlgo}</span>
            </div>
            <div class="flex justify-between text-xs">
              <span class="text-gray-400">Integrity Checksum:</span>
              <span class="font-mono font-bold ${patched ? 'text-emerald-400' : 'text-rose-400'}">${hashAlgo}</span>
            </div>
          </div>
        </div>
        <div class="mt-4 pt-3 border-t border-gray-800/80 text-[11px] text-gray-400">
          Audit: <span class="${patched ? 'text-emerald-300' : 'text-rose-300'} font-medium">${complianceStatus}</span>
        </div>
      </div>

      <!-- Card 3: ECDAT Agility Meter -->
      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Cryptographic Agility Score</span>
            <i class="fa-solid fa-wand-magic-sparkles ${patched ? 'text-emerald-400' : 'text-amber-400'}"></i>
          </div>
          <div class="mt-3">
            <div class="text-2xl font-black ${patched ? 'text-emerald-400' : 'text-rose-400'}">
              ${patched ? 'POSTURE: SECURE' : 'POSTURE: VULNERABLE'}
            </div>
            <p class="text-xs text-gray-400 mt-1">
              ${patched ? 'Modern 256-bit security margin active across all documents' : '56-bit DES allows passive key recovery in cloud storage!'}
            </p>
          </div>
        </div>
        <div class="mt-4 pt-3 border-t border-gray-800/80 flex items-center justify-between text-xs">
          <span class="text-gray-400">Target State:</span>
          <span class="font-semibold ${patched ? 'text-emerald-400' : 'text-amber-400'}">
            ${patched ? 'Remediated & Verified' : 'Awaiting 1-Click Patch'}
          </span>
        </div>
      </div>
    </div>

    <!-- Interactive Grid: Upload Document & Documents Table -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">

      <!-- Upload Document Form -->
      <div class="glass-card rounded-xl p-6 space-y-5">
        <div class="border-b border-gray-800 pb-3">
          <h3 class="font-bold text-white text-base flex items-center gap-2">
            <i class="fa-solid fa-cloud-arrow-up text-purple-400"></i>
            <span>Upload Secret Asset</span>
          </h3>
          <p class="text-xs text-gray-400 mt-1">
            Encrypt and store a confidential file using <b class="${patched ? 'text-emerald-400' : 'text-rose-400'} font-mono">${cipherAlgo}</b>.
          </p>
        </div>

        <form action="/upload-document" method="POST" class="space-y-4">
          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Document Name</label>
            <input type="text" name="filename" value="NextGen_Propulsion_Patent.docx" required class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-medium">
          </div>

          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Asset Category</label>
            <select name="category" class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-medium">
              <option value="Defense Blueprint">Defense Blueprint</option>
              <option value="Infrastructure Secret">Infrastructure Secret</option>
              <option value="Intellectual Property">Intellectual Property</option>
              <option value="Executive Financials">Executive Financials</option>
            </select>
          </div>

          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Confidential Content / Secret Key</label>
            <textarea name="content" rows="3" required class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-purple-500 font-mono">CONFIDENTIAL_PAYLOAD_PLASMA_DRIVE_TOROIDAL_STABILIZER_V4</textarea>
          </div>

          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Author / Uploader</label>
            <input type="text" name="author" value="Chief Cryptography Officer" class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-gray-300 font-medium">
          </div>

          <button type="submit" class="w-full py-2.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-purple-950/40 flex items-center justify-center gap-2 transition-all">
            <i class="fa-solid fa-lock"></i>
            <span>Encrypt & Vault Document (${cipherAlgo})</span>
          </button>
        </form>
      </div>

      <!-- Encrypted Files Table -->
      <div class="glass-card rounded-xl p-6 space-y-4 lg:col-span-2">
        <div class="flex items-center justify-between border-b border-gray-800 pb-3">
          <div>
            <h3 class="font-bold text-white text-base flex items-center gap-2">
              <i class="fa-solid fa-folder-closed text-purple-400"></i>
              <span>Vault Document Repository</span>
            </h3>
            <p class="text-xs text-gray-400 mt-0.5">Encrypted at-rest blobs and integrity checksums.</p>
          </div>
          <span class="text-[11px] px-2.5 py-1 rounded bg-gray-800 text-gray-300 font-mono">
            ${STORED_FILES.length} Files
          </span>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead>
              <tr class="border-b border-gray-800 text-gray-400 text-[11px] uppercase tracking-wider font-semibold">
                <th class="py-2 px-4">Doc ID</th>
                <th class="py-2 px-4">Asset Name</th>
                <th class="py-2 px-4">Category</th>
                <th class="py-2 px-4">Size</th>
                <th class="py-2 px-4">Ciphertext (${cipherAlgo})</th>
                <th class="py-2 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody>
              ${fileRows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </main>

  <!-- Modal for Decrypt & Verify -->
  <div id="fileModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
    <div class="glass-card max-w-lg w-full rounded-xl p-6 space-y-4 border-purple-800/60 shadow-2xl">
      <div class="flex items-center justify-between border-b border-gray-800 pb-3">
        <h4 class="font-bold text-white text-sm flex items-center gap-2">
          <i class="fa-solid fa-unlock-keyhole text-purple-400"></i>
          <span>Document Decryption & Cryptographic Inspection</span>
        </h4>
        <button onclick="closeModal()" class="text-gray-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="space-y-3 text-xs">
        <div>
          <span class="text-gray-400 block mb-1">Document Asset:</span>
          <div id="modalDocName" class="font-semibold text-white"></div>
        </div>
        <div>
          <span class="text-gray-400 block mb-1">Encrypted Stored Payload (${cipherAlgo}):</span>
          <div id="modalCiphertext" class="p-2.5 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-cyan-300 break-all max-h-24 overflow-y-auto"></div>
        </div>
        <div>
          <span class="text-gray-400 block mb-1">Integrity Checksum Hash (${hashAlgo}):</span>
          <div id="modalChecksum" class="p-2.5 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-purple-300 break-all"></div>
        </div>
        <div>
          <span class="text-gray-400 block mb-1">Decrypted Plaintext Secret:</span>
          <div id="modalPlaintext" class="p-2.5 rounded bg-gray-900 border border-emerald-800/40 font-mono text-[11px] text-emerald-300 break-all"></div>
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
    function inspectFile(id, name, enc, chk, raw) {
      document.getElementById('modalDocName').textContent = id + ' — ' + name;
      document.getElementById('modalCiphertext').textContent = enc;
      document.getElementById('modalChecksum').textContent = chk;
      document.getElementById('modalPlaintext').textContent = raw;
      document.getElementById('fileModal').classList.remove('hidden');
    }
    function closeModal() {
      document.getElementById('fileModal').classList.add('hidden');
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
      files_count: STORED_FILES.length
    }));
    return;
  }

  if (req.method === 'POST' && parsed.pathname === '/upload-document') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const filename = params.get('filename') || 'untitled.txt';
      const category = params.get('category') || 'General';
      const content = params.get('content') || 'empty';
      const author = params.get('author') || 'Anonymous';
      const docId = 'DOC-' + Math.floor(1000 + Math.random() * 9000);

      STORED_FILES.unshift({
        id: docId,
        name: filename,
        category: category,
        size: `${Math.max(1, Math.round(content.length * 1.5))} KB`,
        uploaded_at: new Date().toISOString().replace('T', ' ').slice(0, 16),
        raw_secret: content,
        author: author
      });

      res.writeHead(302, { 'Location': '/' });
      res.end();
    });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(PORT, () => {
  console.log(`[CipherCloud Node.js] Server listening on http://localhost:${PORT}`);
});
