"use client";
import { useEffect, useState } from "react";
import {
  ArrowRight,
  Download,
  Route,
  CircleHelp,
  Globe2,
  Clock3,
  Activity,
  Database,
  LoaderCircle,
  AlertTriangle,
} from "lucide-react";
import { requestApi, Scan } from "@/lib/api";
import { MigrationPlan, PlanSummary } from "@/lib/migration";
export function MigrationPlanner({
  scans,
  project,
  token,
  onScan,
}: {
  scans: Scan[];
  project: string;
  token: string;
  onScan: () => void;
}) {
  const [networkSelection, setNetwork] = useState("");
  const [websiteUrl, setWebsiteUrl] = useState("");
  const [websiteJob, setWebsiteJob] = useState<string | null>(null);
  const [submittingScan, setSubmittingScan] = useState(false);
  const pendingWebsite = scans.find((s) => s.id === websiteJob);
  const websiteScanning =
    !!websiteJob &&
    (!pendingWebsite || ["queued", "running"].includes(pendingWebsite.status));
  const network =
    networkSelection ||
    (pendingWebsite?.status === "completed" ? pendingWebsite.id : "");
  const websiteStatus =
    pendingWebsite?.status === "failed" ||
    pendingWebsite?.status === "cancelled"
      ? pendingWebsite.error ||
        "The scan did not complete. Check the address and try again."
      : pendingWebsite?.status === "completed"
        ? "Website inspected. Its evidence is selected below; add context and build your plan."
        : null;
  async function inspectWebsite() {
    if (!websiteUrl.trim()) {
      setError("Enter a website hostname or HTTPS URL.");
      return;
    }
    setSubmittingScan(true);
    setError("");
    setNetwork("");
    setWebsiteJob(null);
    try {
      const job = await requestApi<Scan>("/scan/network", project, token, {
        target: websiteUrl.trim(),
      });
      setWebsiteJob(job.id);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSubmittingScan(false);
    }
  }
  const [related, setRelated] = useState<string[]>([]);
  const [plan, setPlan] = useState<MigrationPlan | null>(null);
  const [history, setHistory] = useState<PlanSummary[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [hasTraffic, setHasTraffic] = useState(false);
  const [form, setForm] = useState({
    current_host: "",
    target_host: "",
    stack: "",
    database: "unknown",
    application_count: "1",
    data_gb: "",
    transfer_mbps: "",
    source: "",
    start_date: "",
    end_date: "",
    total_requests: "",
    total_gb: "",
  });
  const websites = scans.filter(
    (s) => s.kind === "network" && s.status === "completed",
  );
  const artifacts = scans.filter(
    (s) => s.kind !== "network" && s.status === "completed",
  );
  useEffect(() => {
    let active = true;
    requestApi<PlanSummary[]>("/migration/plans", project, token)
      .then((x) => {
        if (active) setHistory(x);
      })
      .catch((e) => {
        if (active) setError(String(e.message));
      });
    return () => {
      active = false;
    };
  }, [project, token]);
  const field = (name: keyof typeof form) => ({
    value: form[name],
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
      setForm((f) => ({ ...f, [name]: e.target.value })),
  });
  async function create(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      const body = {
        scan_ids: [network, ...related],
        current_host: form.current_host || null,
        target_host: form.target_host || null,
        stack: form.stack || null,
        database: form.database,
        application_count: Number(form.application_count),
        data_gb: form.data_gb === "" ? null : Number(form.data_gb),
        transfer_mbps:
          form.transfer_mbps === "" ? null : Number(form.transfer_mbps),
        traffic: hasTraffic
          ? {
              source: form.source,
              start_date: form.start_date,
              end_date: form.end_date,
              total_requests: Number(form.total_requests),
              total_gb: form.total_gb === "" ? null : Number(form.total_gb),
            }
          : null,
      };
      const result = await requestApi<MigrationPlan>(
        "/migration/plans",
        project,
        token,
        body,
      );
      setPlan(result);
      setHistory((h) => [
        { id: result.id, created_at: result.created_at, target: result.target },
        ...h,
      ]);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  async function open(id: string) {
    setError("");
    setBusy(true);
    try {
      setPlan(
        await requestApi<MigrationPlan>(
          `/migration/plans/${id}`,
          project,
          token,
        ),
      );
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }
  function download() {
    if (!plan) return;
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(plan, null, 2)], { type: "application/json" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = `ecdat-migration-${plan.id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <div className="planner">
      <div className="workspace-heading">
        <div>
          <p className="eyebrow">WORKSPACE / MIGRATION</p>
          <h1>Plan your next move</h1>
          <p>One roadmap for cryptographic upgrades and hosting migration.</p>
        </div>
        <span className="status-pill">Evidence-led planning</span>
      </div>
      {error && (
        <div role="alert" className="ec-alert">
          <AlertTriangle size={18} />
          <span>{error}</span>
        </div>
      )}
      <div className="planner-layout">
        <div>
          <form className="ec-panel planner-form" onSubmit={create}>
            <div className="panel-heading">
              <div>
                <h2>1. Connect the evidence</h2>
                <p>Select a website scan and add the context only you know.</p>
              </div>
              <Route size={18} />
            </div>
            <div className="form-body">
              <div className="planner-url-scan">
                <label>
                  Start with a website
                  <input
                    value={websiteUrl}
                    onChange={(e) => setWebsiteUrl(e.target.value)}
                    placeholder="example.org or https://example.org"
                    maxLength={253}
                    aria-label="Website to assess for migration"
                  />
                </label>
                <div className="button-row">
                  <button
                    type="button"
                    className="ec-button"
                    disabled={submittingScan || websiteScanning}
                    onClick={() => void inspectWebsite()}
                  >
                    {submittingScan || websiteScanning ? (
                      <LoaderCircle size={16} className="animate-spin" />
                    ) : (
                      <Globe2 size={16} />
                    )}{" "}
                    {submittingScan || websiteScanning
                      ? "Inspecting website…"
                      : "Inspect website"}
                  </button>
                </div>
                <p className="field-help" role="status">
                  {websiteStatus ||
                    (websiteScanning
                      ? "Checking TLS, certificates and public deployment clues. The completed scan will be selected below."
                      : "Inspect a website you are authorized to test, or choose an existing scan below. No extra trip to the scanner is needed.")}
                </p>
              </div>

              <label>
                Website scan
                <select
                  required
                  value={network}
                  onChange={(e) => setNetwork(e.target.value)}
                >
                  <option value="">Select a completed network scan</option>
                  {websites.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.result?.target} ·{" "}
                      {new Date(s.created_at).toLocaleString()}
                    </option>
                  ))}
                </select>
              </label>
              {!websites.length && (
                <div className="inline-note">
                  <Globe2 size={18} />
                  <p>
                    Run a website scan first. The plan will use its real TLS and
                    deployment evidence.
                    <button
                      type="button"
                      className="text-action"
                      onClick={onScan}
                    >
                      Start a website scan <ArrowRight size={14} />
                    </button>
                  </p>
                </div>
              )}
              {!!artifacts.length && (
                <details>
                  <summary>
                    Link related source or binary scans ({related.length}{" "}
                    selected)
                  </summary>
                  <p className="field-help">
                    Only select artifacts belonging to this website. Their
                    findings inform the cryptography workstream.
                  </p>
                  <div className="artifact-list">
                    {artifacts.map((s) => (
                      <label key={s.id}>
                        <input
                          type="checkbox"
                          checked={related.includes(s.id)}
                          onChange={(e) =>
                            setRelated((ids) =>
                              e.target.checked
                                ? [...ids, s.id]
                                : ids.filter((id) => id !== s.id),
                            )
                          }
                        />
                        <span>
                          {s.kind} · {s.id.slice(0, 8)} ·{" "}
                          {
                            (s.result?.findings || s.result?.detections || [])
                              .length
                          }{" "}
                          findings
                        </span>
                      </label>
                    ))}
                  </div>
                </details>
              )}
              <div className="form-divider">
                <h3>2. Describe the environment</h3>
                <p>
                  Optional details improve the draft. Leave unknown values
                  blank.
                </p>
              </div>
              <div className="form-grid">
                <label>
                  Current hosting
                  <input
                    {...field("current_host")}
                    placeholder="e.g. AWS, a VPS, shared hosting"
                    maxLength={200}
                  />
                </label>
                <label>
                  Target hosting
                  <input
                    {...field("target_host")}
                    placeholder="Where do you want to move?"
                    maxLength={200}
                  />
                </label>
                <label>
                  Application stack
                  <input
                    {...field("stack")}
                    placeholder="e.g. Next.js + FastAPI"
                    maxLength={200}
                  />
                </label>
                <label>
                  Database
                  <select {...field("database")}>
                    <option value="unknown">Not yet known</option>
                    <option value="none">No database / stateless</option>
                    <option value="postgresql">PostgreSQL</option>
                    <option value="mysql">MySQL</option>
                    <option value="mongodb">MongoDB</option>
                    <option value="other">Other database</option>
                  </select>
                </label>
                <label>
                  Applications
                  <input
                    {...field("application_count")}
                    type="number"
                    required
                    min={1}
                    max={100}
                    step={1}
                  />
                </label>
                <label>
                  Data to migrate (GB)
                  <input
                    {...field("data_gb")}
                    type="number"
                    min={0}
                    max={1e9}
                    step="any"
                    placeholder="Unknown"
                  />
                </label>
                <label>
                  Measured transfer speed (Mbps)
                  <input
                    {...field("transfer_mbps")}
                    type="number"
                    min={0.001}
                    max={1e7}
                    step="any"
                    placeholder="Optional; from a transfer test"
                  />
                </label>
              </div>
              <div className="form-divider">
                <h3>3. Add your traffic baseline</h3>
                <p>
                  Public scanning cannot measure your average traffic. Use
                  totals from your hosting, CDN, or analytics dashboard.
                </p>
              </div>
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={hasTraffic}
                  onChange={(e) => setHasTraffic(e.target.checked)}
                />{" "}
                I have traffic totals for a completed period
              </label>
              {hasTraffic && (
                <div className="form-grid">
                  <label>
                    Analytics source
                    <input
                      {...field("source")}
                      required
                      maxLength={200}
                      placeholder="e.g. CDN analytics / access logs"
                    />
                  </label>
                  <label>
                    Total requests
                    <input
                      {...field("total_requests")}
                      type="number"
                      required
                      min={0}
                      max={1e15}
                      step={1}
                    />
                  </label>
                  <label>
                    Period start (inclusive)
                    <input {...field("start_date")} type="date" required />
                  </label>
                  <label>
                    Period end (inclusive)
                    <input {...field("end_date")} type="date" required />
                  </label>
                  <label>
                    Total transferred (GB)
                    <input
                      {...field("total_gb")}
                      type="number"
                      min={0}
                      max={1e12}
                      step="any"
                      placeholder="Optional"
                    />
                  </label>
                </div>
              )}
              <div className="form-actions">
                <small>
                  Creates a saved draft. Review assumptions before scheduling
                  work.
                </small>
                <button className="ec-button" disabled={busy || !network}>
                  {busy ? (
                    <LoaderCircle size={16} className="animate-spin" />
                  ) : (
                    <Route size={16} />
                  )}{" "}
                  Build plan
                </button>
              </div>
            </div>
          </form>
          <section className="ec-panel saved-plans">
            <div className="panel-heading">
              <h2>Saved plans</h2>
              <span className="count-label">Latest 100</span>
            </div>
            {history.length ? (
              <ul>
                {history.map((p) => (
                  <li key={p.id}>
                    <button disabled={busy} onClick={() => void open(p.id)}>
                      <span>
                        {p.target}
                        <small>{new Date(p.created_at).toLocaleString()}</small>
                      </span>
                      <ArrowRight size={16} />
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="empty-state">
                Your migration plans will appear here.
              </p>
            )}
          </section>
        </div>
        <div className="plan-result" aria-live="polite">
          {!plan ? (
            <section className="ec-panel plan-placeholder">
              <div className="plan-placeholder-icon">
                <Route size={28} />
              </div>
              <p className="eyebrow">FROM EVIDENCE TO ACTION</p>
              <h2>Your roadmap starts here.</h2>
              <p>
                Build a draft to see your migration workstreams, missing
                information and a transparent effort range.
              </p>
              <div className="plan-preview-list">
                <span>
                  <Globe2 size={16} /> Hosting & deployment evidence
                </span>
                <span>
                  <Activity size={16} /> Average traffic, when supplied
                </span>
                <span>
                  <Clock3 size={16} /> Effort and transfer estimates
                </span>
                <span>
                  <Database size={16} /> Cutover, validation & rollback
                </span>
              </div>
              <div className="inline-note">
                <CircleHelp size={18} />
                <p>
                  A public scan sees the edge of a website. Confirm the origin,
                  region and deployment method in your hosting account.
                </p>
              </div>
            </section>
          ) : (
            <>
              <section className="ec-panel">
                <div className="panel-heading">
                  <div>
                    <p className="eyebrow">DRAFT MIGRATION PLAN</p>
                    <h2>{plan.target}</h2>
                    <p>
                      Evidence observed{" "}
                      {new Date(plan.evidence.observed_at).toLocaleString()}
                    </p>
                  </div>
                  <button
                    className="ec-button secondary compact"
                    onClick={download}
                  >
                    <Download size={15} /> JSON
                  </button>
                </div>
                <div className="plan-metrics">
                  <article>
                    <span>Engineering effort</span>
                    <strong>
                      {plan.estimate.person_days.join("–")}{" "}
                      <small>person-days</small>
                    </strong>
                    <em>Low-confidence planning range</em>
                  </article>
                  <article>
                    <span>Average daily traffic</span>
                    <strong>
                      {plan.traffic.average_daily_requests === null
                        ? "Unknown"
                        : plan.traffic.average_daily_requests.toLocaleString()}
                      <small>
                        {plan.traffic.average_daily_requests !== null
                          ? " requests"
                          : ""}
                      </small>
                    </strong>
                    <em>
                      {plan.traffic.status === "user_supplied"
                        ? `User supplied · ${plan.traffic.source}`
                        : "Analytics required"}
                    </em>
                  </article>
                  <article>
                    <span>Transfer minimum</span>
                    <strong>
                      {plan.estimate.minimum_transfer_hours === null
                        ? "Unknown"
                        : `${plan.estimate.minimum_transfer_hours} h`}
                    </strong>
                    <em>Theoretical minimum; excludes overhead</em>
                  </article>
                  <article>
                    <span>Expected downtime</span>
                    <strong>Not estimated</strong>
                    <em>Measure in a cutover rehearsal</em>
                  </article>
                </div>
                <div className="plan-evidence">
                  <h3>Observed & inferred</h3>
                  <dl>
                    <div>
                      <dt>Resolved IP</dt>
                      <dd>
                        {plan.evidence.ip_address || "Unknown"}{" "}
                        <span>Observed</span>
                      </dd>
                    </div>
                    <div>
                      <dt>TLS</dt>
                      <dd>
                        {plan.evidence.protocol || "Unknown"}{" "}
                        <span>Observed</span>
                      </dd>
                    </div>
                    <div>
                      <dt>Public hosting clues</dt>
                      <dd>
                        {plan.evidence.deployment?.hosting_hints
                          ?.map((h) => h.provider)
                          .join(", ") || "No identifiable provider hints"}{" "}
                        <span>Inferred</span>
                      </dd>
                    </div>
                    <div>
                      <dt>Origin & physical region</dt>
                      <dd>Not proven by public scanning</dd>
                    </div>
                    <div>
                      <dt>Linked findings</dt>
                      <dd>
                        {plan.evidence.linked_findings} ·{" "}
                        {plan.evidence.urgent_findings} high or critical
                      </dd>
                    </div>
                  </dl>
                  {plan.traffic.status === "user_supplied" && (
                    <p className="field-help">
                      Traffic period: {plan.traffic.start_date} to{" "}
                      {plan.traffic.end_date}. Average bandwidth:{" "}
                      {plan.traffic.average_daily_gb === null
                        ? "not supplied"
                        : `${plan.traffic.average_daily_gb} GB/day`}
                      . {plan.traffic.reason}
                    </p>
                  )}
                </div>
                {!!plan.missing_inputs.length && (
                  <div className="missing-inputs">
                    <h3>Confirm before committing</h3>
                    <div>
                      {plan.missing_inputs.map((x) => (
                        <span key={x}>{x}</span>
                      ))}
                    </div>
                  </div>
                )}
                <details className="estimate-assumptions">
                  <summary>How this estimate was calculated</summary>
                  <p>{plan.estimate.basis}</p>
                  <p>{plan.estimate.formula}</p>
                  <ul>
                    {plan.estimate.assumptions.map((x) => (
                      <li key={x}>{x}</li>
                    ))}
                  </ul>
                </details>
              </section>
              {!!plan.priorities.length && (
                <section className="ec-panel priorities">
                  <div className="panel-heading">
                    <h2>Address these first</h2>
                  </div>
                  {plan.priorities.map((p, i) => (
                    <article key={i}>
                      <span className="status-pill failed">Priority</span>
                      <h3>{p.title}</h3>
                      <p>{p.evidence}</p>
                      <small>Evidence: {p.scan_id.slice(0, 8)}</small>
                    </article>
                  ))}
                </section>
              )}
              <section className="ec-panel roadmap">
                <div className="panel-heading">
                  <div>
                    <h2>Your migration roadmap</h2>
                    <p>
                      Sequential effort ranges · review with the system owner
                    </p>
                  </div>
                </div>
                {plan.phases.map((phase, i) => (
                  <article key={phase.id}>
                    <div className="phase-title">
                      <span>{String(i + 1).padStart(2, "0")}</span>
                      <div>
                        <small>{phase.track}</small>
                        <h3>{phase.title}</h3>
                      </div>
                      <em>{phase.days.join("–")} days</em>
                    </div>
                    <ul>
                      {phase.actions.map((a) => (
                        <li key={a}>{a}</li>
                      ))}
                    </ul>
                    <details>
                      <summary>Validation & rollback</summary>
                      <p>
                        <strong>Ready when:</strong> {phase.validation}
                      </p>
                      <p>
                        <strong>Rollback:</strong> {phase.rollback}
                      </p>
                    </details>
                  </article>
                ))}
              </section>
              <div className="plan-limitations">
                {plan.limitations.map((x) => (
                  <p key={x}>{x}</p>
                ))}
                {plan.references.map((r) => (
                  <a key={r.url} href={r.url} target="_blank" rel="noreferrer">
                    {r.title} ↗
                  </a>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
