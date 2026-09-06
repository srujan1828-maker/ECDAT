const API_BASE = "http://127.0.0.1:8000/api";

// ─── Fetch with abort timeout ──────────────────────────────────────────────────

async function fetchWithTimeout(url: string, options: RequestInit = {}, ms = 6000) {
  const ctrl = new AbortController();
  const id   = setTimeout(() => ctrl.abort(), ms);
  try {
    const res = await fetch(url, { ...options, signal: ctrl.signal });
    clearTimeout(id);
    return res;
  } catch (err) {
    clearTimeout(id);
    throw err;
  }
}

// ─── Core caller — live first, demo fallback ───────────────────────────────────

async function apiCall(endpoint: string, options: RequestInit = {}) {
  try {
    const res = await fetchWithTimeout(`${API_BASE}${endpoint}`, options, 5000);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return { data: await res.json(), cached: false };
  } catch (liveErr) {
    console.warn(`[ECDAT] Live call to ${endpoint} failed (${liveErr}). Falling back to demo data…`);
  }

  const demoEndpoint = endpoint
    .replace(/^\/scan\//, "/demo/")
    .replace(/^\/risk\//, "/demo/")
    .replace(/^\/export\//, "/demo/");

  try {
    const isGet = demoEndpoint.endsWith("overview");
    const res = await fetchWithTimeout(`${API_BASE}${demoEndpoint}`, {
      ...options,
      method: isGet ? "GET" : "POST",
      headers: { "Content-Type": "application/json", ...(options.headers ?? {}) },
    }, 6000);
    if (!res.ok) throw new Error(`Demo HTTP ${res.status}`);
    return { data: await res.json(), cached: true, fallback: true };
  } catch (fbErr) {
    console.error(`[ECDAT] Demo fallback for ${demoEndpoint} also failed:`, fbErr);
    return { data: null, error: String(fbErr) };
  }
}

// ─── Public API ───────────────────────────────────────────────────────────────

/** Overview always fetches the live KG (grows as scans run). */
export async function fetchOverview() {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/demo/overview`, { method: "GET" }, 5000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { data: await res.json(), cached: false };
  } catch (e) {
    console.error("[ECDAT] fetchOverview failed:", e);
    return { data: null, error: String(e) };
  }
}

export async function scanNetwork(target: string, port = 443) {
  return apiCall("/scan/network", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, port }),
  });
}

export async function scanCode(sourceCode: string, language: string = "python") {
  return apiCall("/scan/code", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source_code: sourceCode, language }),
  });
}

export async function fetchPolyglotSamples() {
  try {
    const res = await fetchWithTimeout(`${API_BASE}/polyglot/samples`, { method: "GET" }, 4000);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return { data: await res.json() };
  } catch (e) {
    return { data: null, error: String(e) };
  }
}

export async function scanBinary(rawHex?: string, fileName: string = "firmware_telemetry.bin") {
  return apiCall("/scan/binary", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ raw_hex: rawHex, file_name: fileName }),
  });
}

export async function evaluateAgility(params: {
  hardcoded_primitives_count: number;
  abstracted_primitives_count: number;
  has_provider_abstraction: boolean;
  has_pqc_hybrid_support: boolean;
  automated_cert_rotation: boolean;
  uses_config_driven_crypto: boolean;
}) {
  return apiCall("/agility/evaluate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
}

export async function simulateMigration(params: {
  x_shelf_life: number;
  y_migration_time: number;
  z_crqc_horizon: number;
  critical_findings_count?: number;
  qv_certs_count?: number;
}) {
  return apiCall("/migration/simulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });
}

export async function evaluateMosca(x: number, y: number, z: number) {
  return apiCall("/risk/mosca", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ x, y, z }),
  });
}

export async function exportCbom(
  codeFindings: unknown[],
  networkFindings: unknown[],
  binaryFindings: unknown[] = [],
  targetName: string = "ECDAT-SIH26164-NTRO"
) {
  return apiCall("/export/cbom", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code_findings: codeFindings,
      network_findings: networkFindings,
      binary_findings: binaryFindings,
      target_name: targetName,
    }),
  });
}

export function setDemoMode(_val: boolean) {}
