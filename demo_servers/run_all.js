/**
 * Master Launcher for 3 Dedicated Demo Websites in Node.js
 * 
 * Launches all 3 fully functional web applications simultaneously:
 *   1. Website 1: ApexPay (FinTech Banking & Card Checkout)   -> http://localhost:8081
 *   2. Website 2: MedVault (Healthcare Records & Rx Signing) -> http://localhost:8082
 *   3. Website 3: CipherCloud (Encrypted Enterprise Storage)  -> http://localhost:8083
 * 
 * Usage:
 *   node demo_servers/run_all.js
 */

const { spawn } = require('child_process');
const path = require('path');

const WEBSITES = [
  {
    name: 'Website 1: ApexPay (Banking & Payment Gateway)',
    script: path.join(__dirname, 'website1_apex_pay', 'server.js'),
    port: '8081',
    vuln: 'Broken MD5 password hashing & 56-bit DES card vault'
  },
  {
    name: 'Website 2: MedVault (Clinical EHR & Prescription)',
    script: path.join(__dirname, 'website2_med_vault', 'server.js'),
    port: '8082',
    vuln: 'Quantum-vulnerable 1024-bit RSA doctor prescription keys'
  },
  {
    name: 'Website 3: CipherCloud (Encrypted Secret Vault)',
    script: path.join(__dirname, 'website3_cipher_cloud', 'server.js'),
    port: '8083',
    vuln: '56-bit DES file encryption & weak MD5 integrity checksums'
  }
];

console.log('==================================================================');
console.log('  ECDAT Live Demo Environment: Launching 3 Dedicated Node.js Sites');
console.log('==================================================================');

const processes = [];

// Determine node executable and legacy openssl flag for DES testing
const nodeExe = process.execPath;
const nodeFlags = ['--openssl-legacy-provider'];

for (const site of WEBSITES) {
  console.log(`[*] Starting ${site.name} on http://localhost:${site.port}...`);

  // Try spawning with openssl legacy provider flag
  let p = spawn(nodeExe, [...nodeFlags, site.script], {
    cwd: path.dirname(site.script),
    stdio: 'inherit'
  });

  p.on('error', (err) => {
    // If legacy flag fails on older node, spawn directly
    console.warn(`[!] Retrying ${site.name} without legacy flags: ${err.message}`);
    p = spawn(nodeExe, [site.script], {
      cwd: path.dirname(site.script),
      stdio: 'inherit'
    });
    processes.push({ name: site.name, proc: p });
  });

  processes.push({ name: site.name, proc: p });
}

setTimeout(() => {
  console.log('\n[OK] All 3 dedicated Node.js websites are LIVE in your browser:');
  console.log('  +-------------------------------------------------------------+');
  console.log('  | 1. ApexPay Banking:     http://localhost:8081               |');
  console.log('  |    - Broken MD5 password hashing & 56-bit DES card vault    |');
  console.log('  +-------------------------------------------------------------+');
  console.log('  | 2. MedVault Healthcare: http://localhost:8082               |');
  console.log('  |    - Quantum-vulnerable 1024-bit RSA prescription keys      |');
  console.log('  +-------------------------------------------------------------+');
  console.log('  | 3. CipherCloud Storage: http://localhost:8083               |');
  console.log('  |    - 56-bit DES file encryption & weak MD5 integrity        |');
  console.log('  +-------------------------------------------------------------+');
  console.log('\n------------------------------------------------------------------');
  console.log('  Cloudflare Tunnel Setup (To expose any website publicly):');
  console.log('  Run in a separate terminal:');
  console.log('    cloudflared tunnel --url http://localhost:8081');
  console.log('    cloudflared tunnel --url http://localhost:8082');
  console.log('    cloudflared tunnel --url http://localhost:8083');
  console.log('------------------------------------------------------------------');
  console.log('  How to Demonstrate Live Patching:');
  console.log('  Method 1: ECDAT Web UI (Judge Presentation Panel)');
  console.log('    Open http://localhost:3000/dashboard -> "Live Website Patch Demo"');
  console.log('    Click "1. Audit Code" -> "2. Apply Direct In-Code Patch"');
  console.log('');
  console.log('  Method 2: ECDAT CLI (Terminal in front of judges)');
  console.log('    python -m backend patch --path demo_servers --apply');
  console.log('');
  console.log('  Method 3: Refresh http://localhost:8081, 8082, 8083 in browser');
  console.log('    See the green "SECURITY PATCHED" badges live!');
  console.log('------------------------------------------------------------------');
  console.log('Press Ctrl+C to stop all websites.\n');
}, 1000);

function cleanExit() {
  console.log('\n[*] Stopping all demo websites...');
  for (const item of processes) {
    try {
      item.proc.kill();
    } catch (e) {}
  }
  process.exit(0);
}

process.on('SIGINT', cleanExit);
process.on('SIGTERM', cleanExit);
