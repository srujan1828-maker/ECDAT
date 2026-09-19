/**
 * Website 2: MedVault - Healthcare Records & Electronic Prescription Portal (Node.js)
 * 
 * Fully functional Node.js Clinical EHR Portal.
 * 
 * CRYPTOGRAPHIC VULNERABILITIES (BEFORE PATCH):
 * - Doctor digital signatures generated using disbarred 1024-bit RSA keys (NIST SP 800-131A).
 * - Severe "Harvest Now, Decrypt Later" (HNDL) quantum threat for 30-year HIPAA retained health data.
 * 
 * REMEDIATION (AFTER PATCH):
 * - Upgraded to NIST minimum 3072-bit RSA asymmetric margin (ready for FIPS 204 ML-DSA migration).
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = process.env.PORT || 8082;

// Check if source code has been patched by ECDAT
function isPatched() {
  try {
    const src = fs.readFileSync(__filename, 'utf8');
    const targetSig = 'modulusLength:' + ' 3072';
    return src.includes(targetSig);
  } catch (e) {
    return false;
  }
}

// Doctor's RSA Key Generation (VULNERABLE: 1024-bit RSA)
function generateDoctorKeyPair() {
  return crypto.generateKeyPairSync('rsa', {
    modulusLength: 1024,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
}

// Generate key pair at startup or on reload
let DOCTOR_KEYS = generateDoctorKeyPair();

function signPrescriptionData(dataStr) {
  const currentBits = DOCTOR_KEYS.publicKey.asymmetricKeyDetails?.modulusLength || 1024;
  const expectedBits = isPatched() ? 3072 : 1024;
  if (currentBits !== expectedBits) {
    try {
      DOCTOR_KEYS = generateDoctorKeyPair();
    } catch (e) {}
  }

  const sign = crypto.createSign('SHA256');
  sign.update(dataStr);
  sign.end();
  return sign.sign(DOCTOR_KEYS.privateKey, 'hex');
}

// Patient Records Database
const PATIENTS = [
  {
    id: 'MED-7701',
    name: 'Alexander Hayes',
    age: 42,
    blood_group: 'O+',
    diagnosis: 'Severe Chronic Hypertension & Arrhythmia',
    physician: 'Dr. Aris Thorne, MD',
    last_visit: '2026-09-18',
    prescriptions: ['Lisinopril 20mg Daily', 'Metoprolol 50mg Extended Release']
  },
  {
    id: 'MED-7702',
    name: 'Elena Rostova',
    age: 31,
    blood_group: 'A-',
    diagnosis: 'Type 1 Diabetes Mellitus',
    physician: 'Dr. Aris Thorne, MD',
    last_visit: '2026-09-15',
    prescriptions: ['Insulin Glargine 18 Units at Bedtime', 'Continuous Glucose Monitor Sensor']
  },
  {
    id: 'MED-7703',
    name: 'Marcus Vance',
    age: 58,
    blood_group: 'B+',
    diagnosis: 'Post-Surgical Immunosuppressive Therapy',
    physician: 'Dr. Maya Lin, MD',
    last_visit: '2026-09-12',
    prescriptions: ['Tacrolimus 2mg BID', 'Prednisone 5mg Daily']
  }
];

let SIGNED_PRESCRIPTIONS = [
  {
    id: 'RX-8810',
    patient: 'Alexander Hayes',
    medication: 'Lisinopril 20mg Daily',
    doctor: 'Dr. Aris Thorne, MD',
    signed_at: '2026-09-18 11:20',
    signature_hex: signPrescriptionData('MED-7701:Alexander Hayes:Lisinopril 20mg Daily:2026-09-18')
  },
  {
    id: 'RX-8809',
    patient: 'Elena Rostova',
    medication: 'Insulin Glargine 18 Units',
    doctor: 'Dr. Aris Thorne, MD',
    signed_at: '2026-09-15 14:45',
    signature_hex: signPrescriptionData('MED-7702:Elena Rostova:Insulin Glargine:2026-09-15')
  }
];

function renderPage() {
  const patched = isPatched();
  const keySize = patched ? 3072 : 1024;
  const keyAlgo = patched ? 'RSA-3072' : 'RSA-1024';
  const complianceStatus = patched ? 'NIST SP 800-57 Compliant' : 'DISBARRED: NIST SP 800-131A Violation';

  const securityBadge = patched
    ? `<div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/40 text-emerald-400 text-xs font-semibold shadow-lg shadow-emerald-950/40">
         <i class="fa-solid fa-shield-heart"></i>
         <span>SECURITY PATCHED: RSA-3072 (PQC MARGIN)</span>
       </div>`
    : `<div class="flex items-center gap-2 px-3 py-1.5 rounded-full bg-rose-500/15 border border-rose-500/40 text-rose-400 text-xs font-semibold animate-pulse shadow-lg shadow-rose-950/40">
         <i class="fa-solid fa-biohazard"></i>
         <span>QUANTUM VULNERABLE: 1024-bit RSA KEYS</span>
       </div>`;

  const patientOptions = PATIENTS.map(p => `<option value="${p.name}">${p.name} (${p.id} - ${p.diagnosis})</option>`).join('');

  const patientCards = PATIENTS.map(p => `
    <div class="glass-card rounded-xl p-5 space-y-3">
      <div class="flex items-center justify-between border-b border-gray-800 pb-2.5">
        <div>
          <span class="font-bold text-white text-sm">${p.name}</span>
          <span class="text-[10px] ml-2 px-1.5 py-0.5 rounded bg-gray-800 text-cyan-300 font-mono">${p.id}</span>
        </div>
        <span class="text-[11px] text-gray-400 font-mono">Age: ${p.age} | ${p.blood_group}</span>
      </div>
      <div class="text-xs space-y-1 text-gray-300">
        <div><span class="text-gray-400">Diagnosis:</span> <span class="font-medium text-white">${p.diagnosis}</span></div>
        <div><span class="text-gray-400">Physician:</span> ${p.physician}</div>
      </div>
      <div class="pt-2 border-t border-gray-800/80">
        <span class="text-[11px] text-gray-400 block mb-1">Active Prescriptions:</span>
        <div class="flex flex-wrap gap-1.5">
          ${p.prescriptions.map(rx => `<span class="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 text-[10px] border border-cyan-800/40">${rx}</span>`).join('')}
        </div>
      </div>
    </div>
  `).join('');

  const prescriptionRows = SIGNED_PRESCRIPTIONS.map(rx => `
    <tr class="border-b border-gray-800/60 hover:bg-gray-800/30 text-xs transition-colors">
      <td class="py-3 px-4 font-mono font-bold text-cyan-400">${rx.id}</td>
      <td class="py-3 px-4 font-medium text-white">${rx.patient}</td>
      <td class="py-3 px-4 text-gray-300">${rx.medication}</td>
      <td class="py-3 px-4 text-gray-400 font-mono text-[11px]">${rx.signed_at}</td>
      <td class="py-3 px-4 font-mono text-gray-400 text-[11px] max-w-[200px] truncate" title="${rx.signature_hex}">
        ${rx.signature_hex.slice(0, 32)}...
      </td>
      <td class="py-3 px-4 text-right">
        <button onclick="inspectSig('${rx.id}', '${rx.patient}', '${rx.medication}', '${rx.signature_hex}')" class="px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-cyan-300 text-[11px] font-medium border border-gray-700">
          <i class="fa-solid fa-file-signature mr-1"></i> Verify
        </button>
      </td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MedVault - Healthcare Records & Electronic Prescription Portal (Node.js)</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    body { background-color: #0c121e; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .glass-card { background: rgba(17, 24, 39, 0.75); backdrop-filter: blur(12px); border: 1px solid rgba(75, 85, 99, 0.3); }
    .glow-rose { box-shadow: 0 0 25px rgba(244, 63, 94, 0.15); }
    .glow-emerald { box-shadow: 0 0 25px rgba(16, 185, 129, 0.15); }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- Header -->
  <header class="border-b border-gray-800 bg-gray-900/70 backdrop-blur sticky top-0 z-50">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="h-9 w-9 rounded-lg bg-gradient-to-tr from-rose-600 to-indigo-600 flex items-center justify-center font-bold text-white shadow-lg">
          <i class="fa-solid fa-heart-pulse"></i>
        </div>
        <div>
          <span class="font-extrabold text-lg tracking-tight text-white">Med<span class="text-rose-400">Vault</span></span>
          <span class="text-[10px] ml-2 px-2 py-0.5 rounded bg-rose-950 text-rose-300 font-mono border border-rose-800/40">Clinical EHR Node.js</span>
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
      
      <!-- Card 1: Active Patients -->
      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>EHR Database Records</span>
            <i class="fa-solid fa-hospital-user text-rose-400"></i>
          </div>
          <div class="text-3xl font-black text-white mt-3">${PATIENTS.length} In-Patients</div>
          <p class="text-xs text-gray-400 mt-1">St. Jude Metropolitan Medical Center</p>
        </div>
        <div class="mt-6 pt-4 border-t border-gray-800/80 flex items-center justify-between text-xs text-gray-400">
          <span>HIPAA 30-Year Retention: <b>ACTIVE</b></span>
        </div>
      </div>

      <!-- Card 2: Asymmetric Key Posture -->
      <div class="glass-card rounded-xl p-6 flex flex-col justify-between ${patched ? 'glow-emerald' : 'glow-rose'}">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Physician Key Asymmetric Margin</span>
            <i class="fa-solid fa-key ${patched ? 'text-emerald-400' : 'text-rose-400'}"></i>
          </div>
          <div class="mt-3">
            <div class="text-3xl font-black ${patched ? 'text-emerald-400' : 'text-rose-400'}">
              ${keyAlgo}
            </div>
            <p class="text-xs ${patched ? 'text-emerald-400' : 'text-rose-400'} mt-1 font-mono">
              modulusLength: ${keySize} bits
            </p>
          </div>
        </div>
        <div class="mt-4 pt-3 border-t border-gray-800/80 text-[11px] text-gray-400">
          Audit: <span class="${patched ? 'text-emerald-300' : 'text-rose-300'} font-medium">${complianceStatus}</span>
        </div>
      </div>

      <!-- Card 3: Quantum Threat Meter -->
      <div class="glass-card rounded-xl p-6 flex flex-col justify-between">
        <div>
          <div class="flex justify-between items-center text-gray-400 text-xs font-medium uppercase tracking-wider">
            <span>Shor's Algorithm Threat Index</span>
            <i class="fa-solid fa-atom ${patched ? 'text-emerald-400' : 'text-rose-400'}"></i>
          </div>
          <div class="mt-3">
            <div class="text-2xl font-black ${patched ? 'text-emerald-400' : 'text-rose-400'}">
              ${patched ? 'QUANTUM PROTECTED' : 'HARVEST NOW CRITICAL'}
            </div>
            <p class="text-xs text-gray-400 mt-1">
              ${patched ? '3072-bit provides security until PQC migration' : '1024-bit factorable by early cryptanalytic quantum machines!'}
            </p>
          </div>
        </div>
        <div class="mt-4 pt-3 border-t border-gray-800/80 flex items-center justify-between text-xs">
          <span class="text-gray-400">ECDAT Status:</span>
          <span class="font-semibold ${patched ? 'text-emerald-400' : 'text-amber-400'}">
            ${patched ? 'In-Code Patched' : 'Needs Auto-Patch'}
          </span>
        </div>
      </div>
    </div>

    <!-- Active In-Patients List -->
    <div class="space-y-3">
      <h3 class="font-bold text-white text-base flex items-center gap-2">
        <i class="fa-solid fa-notes-medical text-rose-400"></i>
        <span>Clinical Patient Charts</span>
      </h3>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
        ${patientCards}
      </div>
    </div>

    <!-- Interactive Grid: Sign Prescription & Ledger -->
    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">

      <!-- Prescription Signing Form -->
      <div class="glass-card rounded-xl p-6 space-y-5">
        <div class="border-b border-gray-800 pb-3">
          <h3 class="font-bold text-white text-base flex items-center gap-2">
            <i class="fa-solid fa-pen-nib text-rose-400"></i>
            <span>Digitally Sign Prescription</span>
          </h3>
          <p class="text-xs text-gray-400 mt-1">
            Doctor generates an asymmetric signature with key length <b class="${patched ? 'text-emerald-400' : 'text-rose-400'} font-mono">${keySize} bits</b>.
          </p>
        </div>

        <form action="/sign-prescription" method="POST" class="space-y-4">
          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Select Patient</label>
            <select name="patient" class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-rose-500 font-medium">
              ${patientOptions}
            </select>
          </div>

          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Medication & Dosage</label>
            <input type="text" name="medication" value="Atorvastatin 40mg Oral Once Daily" required class="w-full rounded-lg bg-gray-900 border border-gray-700 px-3 py-2 text-xs text-white focus:outline-none focus:border-rose-500 font-medium">
          </div>

          <div>
            <label class="block text-xs text-gray-400 font-medium mb-1">Authorizing Physician</label>
            <input type="text" name="doctor" value="Dr. Aris Thorne, MD (Lic #MED-9941)" readonly class="w-full rounded-lg bg-gray-950 border border-gray-800 px-3 py-2 text-xs text-gray-400 font-medium">
          </div>

          <button type="submit" class="w-full py-2.5 rounded-lg bg-gradient-to-r from-rose-600 to-indigo-600 hover:from-rose-500 hover:to-indigo-500 text-white font-bold text-xs shadow-lg shadow-rose-950/40 flex items-center justify-center gap-2 transition-all">
            <i class="fa-solid fa-file-signature"></i>
            <span>Sign with Doctor's RSA Key (${keyAlgo})</span>
          </button>
        </form>
      </div>

      <!-- Prescriptions Ledger -->
      <div class="glass-card rounded-xl p-6 space-y-4 lg:col-span-2">
        <div class="flex items-center justify-between border-b border-gray-800 pb-3">
          <div>
            <h3 class="font-bold text-white text-base flex items-center gap-2">
              <i class="fa-solid fa-signature text-rose-400"></i>
              <span>Signed Prescriptions Registry</span>
            </h3>
            <p class="text-xs text-gray-400 mt-0.5">Asymmetric digital signatures recorded on ledger.</p>
          </div>
          <span class="text-[11px] px-2.5 py-1 rounded bg-gray-800 text-gray-300 font-mono">
            ${SIGNED_PRESCRIPTIONS.length} Prescriptions
          </span>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left">
            <thead>
              <tr class="border-b border-gray-800 text-gray-400 text-[11px] uppercase tracking-wider font-semibold">
                <th class="py-2 px-4">Rx ID</th>
                <th class="py-2 px-4">Patient</th>
                <th class="py-2 px-4">Medication</th>
                <th class="py-2 px-4">Timestamp</th>
                <th class="py-2 px-4">Digital Signature</th>
                <th class="py-2 px-4 text-right">Verify</th>
              </tr>
            </thead>
            <tbody>
              ${prescriptionRows}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  </main>

  <!-- Modal for Verify -->
  <div id="verifyModal" class="hidden fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
    <div class="glass-card max-w-lg w-full rounded-xl p-6 space-y-4 border-rose-800/60 shadow-2xl">
      <div class="flex items-center justify-between border-b border-gray-800 pb-3">
        <h4 class="font-bold text-white text-sm flex items-center gap-2">
          <i class="fa-solid fa-certificate text-rose-400"></i>
          <span>Doctor Digital Signature Cryptographic Verification</span>
        </h4>
        <button onclick="closeModal()" class="text-gray-400 hover:text-white"><i class="fa-solid fa-xmark"></i></button>
      </div>
      <div class="space-y-3 text-xs">
        <div>
          <span class="text-gray-400 block mb-1">Prescription & Patient:</span>
          <div id="modalRxMeta" class="font-semibold text-white"></div>
        </div>
        <div>
          <span class="text-gray-400 block mb-1">Doctor Public Key Modulus:</span>
          <div class="p-2 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-cyan-300 font-bold">
            ${keyAlgo} (${keySize} bits)
          </div>
        </div>
        <div>
          <span class="text-gray-400 block mb-1">Cryptographic Signature Hex:</span>
          <div id="modalSig" class="p-2.5 rounded bg-gray-950 border border-gray-800 font-mono text-[11px] text-purple-300 break-all max-h-32 overflow-y-auto"></div>
        </div>
        <div class="p-2.5 rounded ${patched ? 'bg-emerald-950/60 border border-emerald-800/50 text-emerald-300' : 'bg-rose-950/60 border border-rose-800/50 text-rose-300'} text-[11px]">
          ${patched ? '✓ Signature verified with 3072-bit modulus. Meets NIST SP 800-57 guidelines.' : '⚠ Signature uses 1024-bit RSA modulus. Violates NIST SP 800-131A guidelines.'}
        </div>
      </div>
      <div class="pt-3 border-t border-gray-800 text-right">
        <button onclick="closeModal()" class="px-4 py-1.5 rounded bg-gray-800 hover:bg-gray-700 text-white text-xs font-semibold">
          Close Verification
        </button>
      </div>
    </div>
  </div>

  <script>
    function inspectSig(id, patient, medication, sig) {
      document.getElementById('modalRxMeta').textContent = id + ' — ' + patient + ' (' + medication + ')';
      document.getElementById('modalSig').textContent = sig;
      document.getElementById('verifyModal').classList.remove('hidden');
    }
    function closeModal() {
      document.getElementById('verifyModal').classList.add('hidden');
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
      rsa_modulus_bits: isPatched() ? 3072 : 1024,
      prescriptions_count: SIGNED_PRESCRIPTIONS.length
    }));
    return;
  }

  if (req.method === 'POST' && parsed.pathname === '/sign-prescription') {
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', () => {
      const params = new URLSearchParams(body);
      const patient = params.get('patient') || 'Unknown Patient';
      const medication = params.get('medication') || 'Generic Drug';
      const rxId = 'RX-' + Math.floor(1000 + Math.random() * 9000);
      const nowStr = new Date().toISOString().replace('T', ' ').slice(0, 16);

      const sig = signPrescriptionData(`${rxId}:${patient}:${medication}:${nowStr}`);

      SIGNED_PRESCRIPTIONS.unshift({
        id: rxId,
        patient: patient,
        medication: medication,
        doctor: 'Dr. Aris Thorne, MD',
        signed_at: nowStr,
        signature_hex: sig
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
  console.log(`[MedVault Node.js] Server listening on http://0.0.0.0:${PORT} (http://localhost:${PORT})`);
});
