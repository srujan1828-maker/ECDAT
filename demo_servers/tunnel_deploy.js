/**
 * 1-Click Cloudflare Live Tunnel Deployer for ECDAT Demo Websites
 * 
 * Automatically exposes all 3 demo websites on public HTTPS URLs via Cloudflare Quick Tunnels:
 * - Website 1 (ApexPay): http://localhost:8081 -> https://*.trycloudflare.com
 * - Website 2 (MedVault): http://localhost:8082 -> https://*.trycloudflare.com
 * - Website 3 (CipherCloud): http://localhost:8083 -> https://*.trycloudflare.com
 * 
 * Zero configuration required. No account or domain needed.
 */

const { spawn, execSync } = require('child_process');
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const SERVERS = [
  { name: 'ApexPay (FinTech)', port: 8081, file: path.join(__dirname, 'website1_apex_pay', 'server.js') },
  { name: 'MedVault (Healthcare)', port: 8082, file: path.join(__dirname, 'website2_med_vault', 'server.js') },
  { name: 'CipherCloud (Storage)', port: 8083, file: path.join(__dirname, 'website3_cipher_cloud', 'server.js') }
];

const BIN_DIR = path.join(__dirname, '.bin');
const CLOUDFLARED_EXE = process.platform === 'win32'
  ? path.join(BIN_DIR, 'cloudflared.exe')
  : path.join(BIN_DIR, 'cloudflared');

// Ensure local servers are running
function startLocalServer(server) {
  return new Promise((resolve) => {
    const checkReq = http.get(`http://127.0.0.1:${server.port}/`, (res) => {
      console.log(`[OK] ${server.name} already running on port ${server.port}`);
      resolve(null);
    });
    checkReq.on('error', () => {
      console.log(`[*] Starting ${server.name} on port ${server.port}...`);
      const child = spawn(process.execPath, ['--openssl-legacy-provider', server.file], {
        stdio: 'inherit',
        env: { ...process.env, PORT: String(server.port), NODE_OPTIONS: '--openssl-legacy-provider' }
      });
      setTimeout(() => resolve(child), 1500);
    });
  });
}

// Download cloudflared binary if not present
function ensureCloudflared() {
  return new Promise((resolve, reject) => {
    // Check if cloudflared is already in PATH
    try {
      execSync('cloudflared --version', { stdio: 'ignore' });
      return resolve('cloudflared');
    } catch (e) {}

    // Check if local binary exists
    if (fs.existsSync(CLOUDFLARED_EXE)) {
      return resolve(CLOUDFLARED_EXE);
    }

    if (!fs.existsSync(BIN_DIR)) {
      fs.mkdirSync(BIN_DIR, { recursive: true });
    }

    const downloadUrl = process.platform === 'win32'
      ? 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-windows-amd64.exe'
      : process.platform === 'darwin'
      ? 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-darwin-amd64'
      : 'https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64';

    console.log(`[*] Downloading portable cloudflared binary from GitHub releases...`);
    console.log(`    Source: ${downloadUrl}`);

    function getWithRedirect(url, dest) {
      https.get(url, (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return getWithRedirect(res.headers.location, dest);
        }
        if (res.statusCode !== 200) {
          return reject(new Error(`Failed to download cloudflared: HTTP ${res.statusCode}`));
        }
        const file = fs.createWriteStream(dest);
        res.pipe(file);
        file.on('finish', () => {
          file.close(() => {
            if (process.platform !== 'win32') {
              fs.chmodSync(dest, 0o755);
            }
            console.log(`[OK] Cloudflared ready at: ${dest}`);
            resolve(dest);
          });
        });
      }).on('error', (err) => {
        fs.unlink(dest, () => {});
        reject(err);
      });
    }

    getWithRedirect(downloadUrl, CLOUDFLARED_EXE);
  });
}

// Start Cloudflare Quick Tunnel for a port and capture URL
function startTunnel(binPath, port, serverName) {
  return new Promise((resolve) => {
    const child = spawn(binPath, ['tunnel', '--url', `http://127.0.0.1:${port}`], {
      stdio: ['ignore', 'pipe', 'pipe']
    });

    let detectedUrl = null;
    const urlRegex = /https:\/\/[a-zA-Z0-9-]+\.trycloudflare\.com/g;

    function parseOutput(data) {
      const text = data.toString();
      const match = text.match(urlRegex);
      if (match && !detectedUrl) {
        detectedUrl = match[0];
        console.log(`\n  =============================================================`);
        console.log(`  [+] LIVE PUBLIC URL for ${serverName}:`);
        console.log(`      >> ${detectedUrl} <<`);
        console.log(`  =============================================================\n`);
        resolve({ name: serverName, port, publicUrl: detectedUrl, process: child });
      }
    }

    child.stdout.on('data', parseOutput);
    child.stderr.on('data', parseOutput);

    child.on('error', (err) => {
      console.error(`[-] Failed to start tunnel for ${serverName}:`, err.message);
      resolve({ name: serverName, port, publicUrl: null, process: null });
    });

    // Timeout fallback after 20s
    setTimeout(() => {
      if (!detectedUrl) {
        resolve({ name: serverName, port, publicUrl: `http://localhost:${port} (Tunnel timeout)`, process: child });
      }
    }, 20000);
  });
}

async function main() {
  console.log('=====================================================================');
  console.log('  ECDAT: 1-Click Cloudflare Public Tunnel Deployer (Judge Demo)');
  console.log('=====================================================================\n');

  // Step 1: Start local servers
  for (const server of SERVERS) {
    await startLocalServer(server);
  }

  // Step 2: Get cloudflared binary
  let binPath;
  try {
    binPath = await ensureCloudflared();
  } catch (err) {
    console.error('[-] Could not download cloudflared automatically:', err.message);
    console.log('\n[*] Fallback: You can also use npx localtunnel:');
    console.log('    npx localtunnel --port 8081');
    console.log('    npx localtunnel --port 8082');
    console.log('    npx localtunnel --port 8083');
    process.exit(1);
  }

  // Step 3: Launch tunnels
  console.log('[*] Establishing Cloudflare Quick Tunnels...');
  const tunnels = [];
  for (const server of SERVERS) {
    console.log(`[*] Exposing ${server.name} (port ${server.port})...`);
    const res = await startTunnel(binPath, server.port, server.name);
    tunnels.push(res);
  }

  console.log('\n=====================================================================');
  console.log('  ALL 3 DEMO WEBSITES ARE LIVE ON PUBLIC HTTPS URLS!');
  console.log('=====================================================================');
  tunnels.forEach(t => {
    console.log(`  - ${t.name}:`);
    console.log(`      Local:  http://localhost:${t.port}`);
    console.log(`      Public: ${t.publicUrl}`);
  });
  console.log('=====================================================================');
  console.log('  Press CTRL+C anytime to stop tunnels and exit.\n');

  process.on('SIGINT', () => {
    console.log('\n[*] Stopping all tunnels...');
    tunnels.forEach(t => { if (t.process) t.process.kill(); });
    process.exit(0);
  });
}

main().catch(err => {
  console.error('[-] Fatal error:', err);
  process.exit(1);
});
