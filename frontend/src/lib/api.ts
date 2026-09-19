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
export type PcapSession = {
  client_ip: string;
  server_ip: string;
  client_port: number;
  server_port: number;
  sni?: string;
  tls_version?: string;
  offered_ciphers?: string[];
  selected_cipher?: string;
  supported_groups?: string[];
  selected_group?: string;
  ja3_string?: string;
  ja3_fingerprint?: string;
  ja4_fingerprint?: string;
  has_pqc_hybrid?: boolean;
  is_quantum_vulnerable?: boolean;
};

export type ScanResult = {
  findings?: Finding[];
  detections?: Finding[];
  target?: string;
  protocol?: string;
  cipher_name?: string;
  key_exchange?: string;
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
  sessions?: PcapSession[];
  packets_analyzed?: number;
  tls_handshakes_detected?: number;
  pqc_sessions_count?: number;
  quantum_vulnerable_count?: number;
  evidence_records?: EvidenceRecord[];
  summary?: Record<string, unknown>;
};
export type Scan = {
  id: string;
  project: string;
  kind: "code" | "network" | "binary" | "pcap";
  status: "queued" | "running" | "completed" | "failed" | "cancelled";
  created_at: string;
  input_hash: string;
  engine_version: string;
  result: ScanResult | null;
  error: string | null;
};

export type EvidenceRecord = {
  asset_id: string;
  asset_type: string;
  algorithm: string;
  cryptographic_role: string;
  source_surface: string;
  evidence_type: string;
  location_endpoint: string;
  confidence: string;
  timestamp: string;
  input_hash: string;
  engine_version: string;
  severity: string;
  description: string;
  quantum_vulnerable: boolean | null;
  provenance: {
    detector_engine: string;
    detection_technique?: string;
    rule_or_signature?: string;
    raw_match?: string;
    parameters?: Record<string, unknown>;
  };
};

export type DiffItem = {
  primitive: string;
  category: string;
  surface: string;
  location: string;
  severity: string;
  description: string;
  evidence_id?: string;
};

export type VerificationReport = {
  verdict: "VERIFIED" | "NOT_VERIFIED" | "INCONCLUSIVE";
  confidence: string;
  rationale: string;
  baseline_scan_ids: string[];
  post_migration_scan_ids: string[];
  timestamp: string;
  retired_weaknesses: DiffItem[];
  introduced_protections: DiffItem[];
  persisting_risks: DiffItem[];
  regressions: DiffItem[];
  summary: {
    baseline_total: number;
    post_migration_total: number;
    baseline_weak_count: number;
    retired_weaknesses_count: number;
    persisting_risks_count: number;
    regressions_count: number;
    introduced_protections_count: number;
    risk_reduction_percentage: number;
  };
  audit_notes: string[];
};

export type RegulatoryControl = {
  standard: string;
  jurisdiction: string;
  requirement: string;
  deadline_or_milestone?: string;
  applies_to: string;
  status: string;
  source_url: string;
};

export type StandardMapping = {
  category: string;
  legacy_primitive: string;
  target_standard: string;
  security_strength_bits: number;
  controls: RegulatoryControl[];
  guidance: string;
};

export type QuantumResourceEstimate = {
  target_algorithm: string;
  key_size_bits: number;
  attack_type: string;
  logical_qubits: number;
  physical_qubits_estimate: number;
  toffoli_gate_count: number;
  surface_code_distance: number;
  physical_error_rate_assumed: number;
  surface_code_cycle_time_us: number;
  estimated_runtime_hours: number;
  uncertainty_range_hours: string;
  literature_citations: string[];
  assumptions: string[];
  disclaimer: string;
};

export type MigrationPatch = {
  pattern_id: string;
  target_language: string;
  file_path: string;
  original_code: string;
  patched_code: string;
  unified_diff: string;
  transformation_description: string;
  generated_regression_test: string;
  verification_status: string;
  test_output?: string;
  re_scan_summary?: {
    previous_findings_count: number;
    remaining_findings_count: number;
    status: string;
  };
};

export type ApplyPatchResponse = {
  status: string;
  file_path: string;
  relative_path: string;
  backup_created: boolean;
  backup_path?: string;
  bytes_written: number;
  remaining_findings_count: number;
  weakness_eliminated: boolean;
};

export type PatchedFileResult = {
  path: string;
  language: string;
  original_code: string;
  patched_code: string;
  unified_diff: string;
  pattern_id: string;
  transformation: string;
  verification_status: string;
  test_output?: string;
  findings_before: number;
  findings_after: number;
  weakness_eliminated: boolean;
};

export type CodebasePatchResponse = {
  summary: {
    total_files_scanned: number;
    vulnerable_files_count: number;
    clean_files_count: number;
    vulnerabilities_found: number;
    vulnerabilities_remediated: number;
    remaining_vulnerabilities: number;
    remediation_rate_percent: number;
    languages_detected: string[];
    all_verified: boolean;
  };
  patched_files: PatchedFileResult[];
  clean_file_paths: string[];
};

export type OverviewStats = {
  system_name: string;
  environment: string;
  posture_status: string;
  subtitle: string;
  metrics: {
    crypto_assets: number;
    crypto_assets_sub: string;
    quantum_relevant: number;
    quantum_relevant_sub: string;
    hndl_exposure: number;
    hndl_exposure_sub: string;
    hybrid_pqc_capable: number;
    hybrid_pqc_capable_sub: string;
    completed_scans: number;
    completed_scans_sub: string;
  };
  risk_distribution: {
    total_assets: number;
    critical_shor: number;
    safe_grover_pqc: number;
    legacy_insecure: number;
  };
  algorithm_family_distribution: {
    name: string;
    count: number;
    percentage: number;
    color: string;
  }[];
  multi_surface_coverage: {
    name: string;
    status: string;
    variant: string;
  }[];
  action_queue: {
    level: string;
    title: string;
    detail: string;
    rationale: string;
  }[];
  threat_timeline: {
    algorithm: string;
    years_remaining: number;
    percent: number;
    color: string;
  }[];
};

export type CustomCryptoFinding = {
  file_path: string;
  line_number: number;
  candidate_snippet: string;
  classification: string;
  is_custom_crypto: boolean;
  confidence: number;
  explanation: string;
  human_review_status: string;
  detection_method: string;
};

export type BenchmarkMetrics = {
  total_samples: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
  accuracy: number;
  details: Array<{
    id: string;
    name: string;
    actual: boolean;
    predicted: boolean;
    verdict: string;
    confidence: number;
    explanation: string;
  }>;
};

export type SihDemoStep = {
  step_number: number;
  title: string;
  summary: string;
  data: Record<string, unknown>;
};

export type SihDemoExecution = {
  status: string;
  total_steps: number;
  steps: SihDemoStep[];
  cbom: {
    components?: Array<Record<string, unknown>>;
    [key: string]: unknown;
  };
  verification: VerificationReport;
  runtime_trace_summary: Record<string, unknown>;
};

export function cleanErrorMessage(raw: string, status?: number): string {
  if (!raw) return `HTTP ${status || "Error"}`;
  if (/<[a-z][\s\S]*>/i.test(raw)) {
    if (/<title>Blocked<\/title>/i.test(raw) || /Ray ID:/i.test(raw) || /Cloudflare/i.test(raw)) {
      const rayMatch = raw.match(/Ray ID:\s*<code[^>]*>([a-f0-9]+)<\/code>|data-ray="([a-f0-9]+)"/i);
      const rayId = rayMatch ? (rayMatch[1] || rayMatch[2]) : "";
      return `Security Firewall Block (HTTP 403): Cloudflare WAF or network policy blocked the request${rayId ? ` (Ray ID: ${rayId})` : ''}. ` +
        `Scanning unencoded source code through Cloudflare tunnels triggers WAF rules. Payload encoding has been enabled, or you can access the dashboard directly at http://localhost:3000.`;
    }
    const titleMatch = raw.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : "HTTP Error";
    const stripped = raw
      .replace(/<style[\s\S]*?<\/style>/gi, "")
      .replace(/<script[\s\S]*?<\/script>/gi, "")
      .replace(/<svg[\s\S]*?<\/svg>/gi, "")
      .replace(/<[^>]+>/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 300);
    return `${title} (${status ? `HTTP ${status}` : "Error"}): ${stripped}`;
  }
  return raw;
}

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

  const separator = path.includes("?") ? "&" : "?";
  const url = `/api${path}${separator}project=${encodeURIComponent(project)}`;

  const response = await fetch(url, {
    method: body === undefined ? "GET" : "POST",
    headers,
    body:
      body instanceof FormData
        ? body
        : body === undefined
          ? undefined
          : JSON.stringify(body),
    signal: AbortSignal.timeout(300000),
    cache: "no-store",
  });

  let data: any;
  const text = await response.text();
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    data = { detail: cleanErrorMessage(text, response.status) };
  }

  if (!response.ok) {
    const rawDetail = typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail || data);
    throw new Error(cleanErrorMessage(rawDetail, response.status));
  }
  return data;
}
