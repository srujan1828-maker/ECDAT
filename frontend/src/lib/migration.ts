export type PlanSummary = { id: string; created_at: string; target: string };
export type MigrationPlan = PlanSummary & {
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
