const API_BASE = "http://127.0.0.1:8000/api";

// ─── Fetch with abort timeout ──────────────────────────────────────────────────

async function fetchWithTimeout(url: string, options: RequestInit = {}, ms = 5000) {
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
  // 1. Try live endpoint (4 s hard timeout)
  try {
    const res = await fetchWithTimeout(`${API_BASE}${endpoint}`, options, 4000);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return { data: await res.json(), cached: false };
  } catch (liveErr) {
    console.warn(`[ECDAT] Live call to ${endpoint} failed (${liveErr}). Falling back to demo data…`);
  }

  // 2. Fall back to demo endpoint using the same request body so computed
  //    results (e.g. Mosca sliders) stay correct.
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

/** Overview always fetches the live KG (grows as scans run). Falls back to seeded graph. */
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

export async function scanCode(sourceCode: string) {
  return apiCall("/scan/code", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ source_code: sourceCode }),
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
  targetName: string,
) {
  return apiCall("/export/cbom", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      code_findings: codeFindings,
      network_findings: networkFindings,
      target_name: targetName,
    }),
  });
}

// Keep for compatibility — no longer used by UI but exported to avoid import errors
export function setDemoMode(_val: boolean) {}
