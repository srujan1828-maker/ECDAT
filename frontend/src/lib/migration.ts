import type { EnvironmentEvidence, PQEvidence } from "./api";
export type PlanSummary = { id: string; created_at: string; target: string };
export type MigrationPlan = PlanSummary & {
  environment?: EnvironmentEvidence;
  input_sources?: Record<string, string>;
  cryptographic_migration?: {
    scope: string;
    tls_key_exchange: PQEvidence;
    upgrades: {
      current: string;
      role: string;
      target: string;
      reason: string;
      evidence: string;
      action: string;
      validation: string;
      reference?: string;
    }[];
    limitations: string[];
    references: { title: string; url: string }[];
  };
  status: string;
  scan_ids: string[];
  missing_inputs: string[];
  limitations: string[];
  evidence: {
    observed_at: string;
    ip_address: string;
    protocol: string;
    linked_findings: number;
    urgent_findings: number;
    deployment?: {
      status?: string;
      origin_provider?: string | null;
      origin_region?: string | null;
      headers?: Record<string, string>;
      hosting_hints?: {
        provider: string;
        confidence: string;
        evidence: string;
      }[];
    };
  };
  traffic: {
    status: string;
    source?: string;
    start_date?: string;
    end_date?: string;
    average_daily_requests: number | null;
    average_daily_gb: number | null;
    reason: string;
  };
  estimate: {
    person_days: number[];
    minimum_transfer_hours: number | null;
    downtime_minutes: number | null;
    basis: string;
    formula: string;
    assumptions: string[];
  };
  priorities: {
    priority: string;
    title: string;
    evidence: string;
    scan_id: string;
  }[];
  phases: {
    id: string;
    track: string;
    title: string;
    days: number[];
    actions: string[];
    validation: string;
    rollback: string;
  }[];
  references: { title: string; url: string }[];
};
