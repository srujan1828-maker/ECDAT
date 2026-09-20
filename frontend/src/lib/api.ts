export type EnvironmentEvidence = {
  status: string;
  signals: {
    category: string;
    value: string;
    evidence: string;
    source: string;
    confidence: string;
  }[];
  limitations?: string[];
};
export type PQEvidence = {
  status: string;
  reason: string;
  scanner_version?: string;
  supported_groups: string[];
  scope: string;
  tests: {
    group: string;
    status: string;
    reason?: string;
    evidence?: string;
    negotiated_group?: string;
  }[];
};
export type Finding = {
  primitive: string;
  severity?: string;
  file?: string;
  line?: number;
  offset?: string;
  confidence?: string;
  issue?: string;
  description?: string;
  engine?: string;
};
export type ScanResult = {
  findings?: Finding[];
  detections?: Finding[];
  target?: string;
  protocol?: string;
  cipher_name?: string;
  pqc_status?: string;
  quantum_vulnerable?: boolean | null;
  hndl_risk?: string;
  hndl_rationale?: string;
  post_quantum?: PQEvidence;
  certificate?: Record<string, unknown>;
  coverage?: unknown;
  dependencies?: unknown[];
  status?: string;
  limitations?: string[];
  deployment?: {
    environment?: EnvironmentEvidence;
    status: string;
    status_code?: number;
    hosting_hints?: {
      provider: string;
      confidence: string;
      evidence: string;
    }[];
    headers?: Record<string, string>;
    limitations?: string[];
  };
  protocol_tests?: unknown[];
  cipher_tests?: unknown[];
  members?: unknown[];
};
export type Scan = {
  id: string;
  project: string;
  kind: "code" | "network" | "binary";
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  created_at: string;
  input_hash: string;
  engine_version: string;
  result: ScanResult | null;
  error: string | null;
};

export async function requestApi<T>(
  path: string,
  project: string,
  token: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (body && !(body instanceof FormData))
    headers["Content-Type"] = "application/json";
  const response = await fetch(
    `/api${path}?project=${encodeURIComponent(project)}`,
    {
      method: body === undefined ? "GET" : "POST",
      headers,
      body:
        body instanceof FormData
          ? body
          : body === undefined
            ? undefined
            : JSON.stringify(body),
      signal: AbortSignal.timeout(35000),
      cache: "no-store",
    },
  );
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : JSON.stringify(data.detail || data),
    );
  return data;
}
