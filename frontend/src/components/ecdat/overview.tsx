"use client";
import { useMemo, useState, useSyncExternalStore } from "react";
import {
  Bar,
  BarChart,
  Line,
  LineChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts";
import {
  ArrowRight,
  Activity,
  CheckCircle2,
  Globe2,
  Code2,
  Binary,
  Route,
  X,
  ShieldAlert,
  Gauge,
  Radar,
  FileCheck2,
  Scale,
  FlaskConical,
  PlayCircle,
  Wrench,
} from "lucide-react";
import { Scan } from "@/lib/api";
import { CorrelationGraph } from "@/components/ecdat/correlation-graph";
export function Overview({
  scans,
  connected,
  onStart,
  onInspect,
  onMigration,
  onVerification,
  onStandards,
  onExperimental,
  onSihDemo,
  onPatchMigration,
}: {
  scans: Scan[];
  connected: boolean;
  onStart: (kind: "network" | "code" | "binary") => void;
  onInspect: (id: string) => void;
  onMigration: () => void;
  onVerification?: () => void;
  onStandards?: () => void;
  onExperimental?: () => void;
  onSihDemo?: () => void;
  onPatchMigration?: () => void;
}) {
  const [tipsDismissed, setTipsDismissed] = useState(false);
  const tipsSeen = useSyncExternalStore(
    () => () => undefined,
    () => window.localStorage.getItem("ecdat-starting-tips-seen") === "true",
    () => true,
  );
  const tips = !tipsSeen && !tipsDismissed;

  function dismissTips() {
    window.localStorage.setItem("ecdat-starting-tips-seen", "true");
    setTipsDismissed(true);
  }

  const [days, setDays] = useState(7);
  const complete = scans.filter((s) => s.status === "completed");
  const active = scans.filter((s) => ["queued", "running"].includes(s.status));
  const findings = complete.flatMap(
    (s) => s.result?.findings || s.result?.detections || [],
  );
  const severityCounts = findings.reduce(
    (counts, finding) => {
      const level = finding as { severity?: string; risk?: string };
      const severity = String(
        level.severity || level.risk || "unknown",
      ).toLowerCase();
      if (severity.includes("critical")) counts.critical += 1;
      else if (severity.includes("high")) counts.high += 1;
      else if (severity.includes("medium")) counts.medium += 1;
      else if (severity.includes("low")) counts.low += 1;
      else counts.unknown += 1;
      return counts;
    },
    { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
  );
  const riskScore = Math.min(
    100,
    severityCounts.critical * 28 +
      severityCounts.high * 14 +
      severityCounts.medium * 6 +
      severityCounts.low * 2,
  );
  const posture = !findings.length
    ? "Awaiting evidence"
    : riskScore >= 55
      ? "Action required"
      : riskScore >= 20
        ? "Review recommended"
        : "Controlled";
  const quantumReadiness = complete.length ? Math.max(18, 100 - riskScore) : 0;
  const migrationReadiness = complete.length ? Math.max(12, 86 - riskScore) : 0;
  const severityChartData = [
    { name: "Critical", value: severityCounts.critical, color: "var(--ecdat-critical)" },
    { name: "High", value: severityCounts.high, color: "var(--ecdat-high)" },
    { name: "Medium", value: severityCounts.medium, color: "var(--ecdat-medium)" },
    { name: "Low", value: severityCounts.low, color: "var(--ecdat-low)" },
  ].filter((item) => item.value > 0);
  const data = useMemo(
    () =>
      Array.from({ length: days }, (_, i) => {
        const d = new Date();
        d.setHours(0, 0, 0, 0);
        d.setDate(d.getDate() - days + 1 + i);
        const end = new Date(d);
        end.setDate(end.getDate() + 1);
        return {
          date: d.toLocaleDateString(undefined, {
            month: "short",
            day: "numeric",
          }),
          scans: scans.filter(
            (s) => new Date(s.created_at) >= d && new Date(s.created_at) < end,
          ).length,
        };
      }),
    [scans, days],
  );
  return (
    <div className="overview">
      <div className="workspace-heading">
        <div>
          <p className="eyebrow">WORKSPACE / OVERVIEW</p>
          <h1>Discovery command center</h1>
          <p>Understand what you have. Decide what changes next.</p>
        </div>
        <button className="ec-button" onClick={() => onStart("network")}>
          New scan <ArrowRight size={16} />
        </button>
      </div>
      {tips && (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/45 p-4"
          role="dialog"
          aria-modal="true"
          aria-labelledby="tips-heading"
        >
          <section className="w-full max-w-2xl rounded-xl border border-subtle bg-surface p-6 shadow-2xl">
            <div className="flex items-start justify-between gap-4">
              <div>
                <p className="eyebrow">WELCOME TO ECDAT</p>
                <h2 id="tips-heading" className="mt-2 text-xl font-semibold">
                  Your first scan, in three steps
                </h2>
                <p className="mt-2 text-sm text-quiet">
                  This quick guide is shown once. You can start with any scan
                  type when you are ready.
                </p>
              </div>
              <button
                onClick={dismissTips}
                aria-label="Close starting tips"
                className="rounded p-1 text-quiet hover:bg-surface-raised"
              >
                <X size={18} />
              </button>
            </div>
            <div className="mt-5 grid gap-3 sm:grid-cols-3">
              {[
                [
                  "01",
                  "Choose a target",
                  "Start with a website, code, or firmware you are authorized to inspect.",
                ],
                [
                  "02",
                  "Review the evidence",
                  "Use scan results to understand findings and coverage.",
                ],
                [
                  "03",
                  "Plan your next move",
                  "Create a report and prioritize remediation.",
                ],
              ].map(([n, title, text]) => (
                <div
                  key={n}
                  className="rounded-lg border border-subtle bg-canvas/50 p-4"
                >
                  <span className="font-mono text-xs text-teal">{n}</span>
                  <h3 className="mt-2 text-sm font-semibold">{title}</h3>
                  <p className="mt-1 text-xs leading-relaxed text-quiet">
                    {text}
                  </p>
                </div>
              ))}
            </div>
            <div className="mt-6 flex justify-end">
              <button className="ec-button" onClick={dismissTips}>
                Get started <ArrowRight size={15} />
              </button>
            </div>
          </section>
        </div>
      )}
      <section className="command-posture">
        <div className="posture-overview">
          <div className="posture-kicker">
            <ShieldAlert size={17} /> SECURITY POSTURE
          </div>
          <div className="posture-score-row">
            <strong>
              {complete.length ? String(100 - riskScore).padStart(2, "0") : "—"}
            </strong>
            <div>
              <h2>{posture}</h2>
              <p>
                {complete.length
                  ? `${findings.length} recorded findings across ${complete.length} completed scans.`
                  : "Run a scan to establish your cryptographic risk baseline."}
              </p>
            </div>
          </div>
          <div className="posture-actions">
            <button
              className="ec-button compact"
              onClick={() => onStart("network")}
            >
              Run network scan <ArrowRight size={14} />
            </button>
            <button className="text-action" onClick={onMigration}>
              Open migration plan <Route size={14} />
            </button>
          </div>
        </div>
        <div className="severity-strip" aria-label="Finding severity summary">
          {[
            ["Critical", severityCounts.critical, "critical"],
            ["High", severityCounts.high, "high"],
            ["Medium", severityCounts.medium, "medium"],
            ["Low", severityCounts.low, "low"],
          ].map(([label, value, severity]) => (
            <div className={`severity-item ${severity}`} key={String(label)}>
              <span>{String(label)}</span>
              <strong>{String(value)}</strong>
            </div>
          ))}
          <p>
            <span className="status-dot" />{" "}
            {connected
              ? "Evidence service connected"
              : "Connect a project to load evidence"}
          </p>
        </div>
      </section>
      <section className="readiness-grid" aria-label="Readiness summary">
        {[
          [
            Gauge,
            "Quantum readiness",
            quantumReadiness,
            "Exposure measured against the current inventory.",
          ],
          [
            Radar,
            "Migration readiness",
            migrationReadiness,
            "Planning confidence based on available evidence.",
          ],
        ].map(([Icon, label, value, detail]) => {
          const ReadinessIcon = Icon as typeof Gauge;
          return (
            <article className="readiness-card" key={String(label)}>
              <div
                className="readiness-ring"
                style={
                  { "--readiness": `${String(value)}%` } as React.CSSProperties
                }
              >
                <span>{value ? `${String(value)}%` : "—"}</span>
              </div>
              <div>
                <ReadinessIcon size={17} />
                <h2>{String(label)}</h2>
                <p>{String(detail)}</p>
              </div>
            </article>
          );
        })}
      </section>
      <div className="metric-grid">
        {[
          [
            CheckCircle2,
            "Completed scans",
            complete.length,
            "Saved in this project",
          ],
          [Activity, "In progress", active.length, "Queued or running"],
          [
            Code2,
            "Recorded findings",
            findings.length,
            "Across source & binary scans",
          ],
          [
            Globe2,
            "Website scans",
            complete.filter((s) => s.kind === "network").length,
            "Completed TLS observations",
          ],
        ].map(([Icon, title, value, note]) => {
          const I = Icon as typeof Activity;
          return (
            <article className="metric" key={String(title)}>
              <div>
                <span>{String(title)}</span>
                <I size={16} />
              </div>
              <strong>{String(value)}</strong>
              <small>{String(note)}</small>
            </article>
          );
        })}
      </div>
      <div className="overview-charts">
        <section className="ec-panel">
          <div className="panel-heading"><div><h2>Surface comparison</h2><p>Completed discoveries by evidence surface</p></div></div>
          <div className="h-[210px]">
            <ResponsiveContainer width="100%" height="100%"><BarChart data={[
              { surface: "Source", scans: complete.filter((s) => s.kind === "code").length },
              { surface: "Binary", scans: complete.filter((s) => s.kind === "binary").length },
              { surface: "TLS", scans: complete.filter((s) => s.kind === "network").length },
            ]} margin={{ top: 15, right: 12, left: -20, bottom: 0 }}>
              <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 5" /><XAxis dataKey="surface" tick={{ fill: "var(--muted-text)", fontSize: 11 }} axisLine={false} tickLine={false} /><YAxis allowDecimals={false} tick={{ fill: "var(--muted-text)", fontSize: 11 }} axisLine={false} tickLine={false} /><Tooltip contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text)", borderRadius: 8 }} /><Bar dataKey="scans" name="Completed scans" fill="var(--teal)" radius={[5, 5, 0, 0]} />
            </BarChart></ResponsiveContainer>
          </div>
        </section>
        <section className="ec-panel">
          <div className="panel-heading">
            <div>
              <h2>Scan activity</h2>
              <p>Submissions per day · latest 200 records · local time</p>
            </div>
            <select
              aria-label="Chart period"
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            >
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
            </select>
          </div>
          {!scans.length ? (
            <div className="chart-empty">
              <Activity size={28} />
              <strong>
                {connected
                  ? "Your activity starts here"
                  : "Waiting for a connection"}
              </strong>
              <p>
                {connected
                  ? "Run a scan to build a real activity history."
                  : "Check connection settings to load saved scans."}
              </p>
            </div>
          ) : (
            <div className="activity-chart">
              <ResponsiveContainer width="100%" height={210}>
                <LineChart
                  data={data}
                  margin={{ top: 15, right: 16, left: -20, bottom: 0 }}
                >
                  <CartesianGrid
                    vertical={false}
                    stroke="var(--border)"
                    strokeDasharray="3 5"
                  />
                  <XAxis
                    dataKey="date"
                    tick={{ fill: "var(--muted-text)", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                    minTickGap={20}
                  />
                  <YAxis
                    allowDecimals={false}
                    tick={{ fill: "var(--muted-text)", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      background: "var(--surface)",
                      border: "1px solid var(--border)",
                      color: "var(--text)",
                      borderRadius: 8,
                    }}
                  />
                  <Line
                    dataKey="scans"
                    name="Scans submitted"
                    type="monotone"
                    stroke="var(--teal)"
                    strokeWidth={2}
                    dot={{ fill: "var(--teal)", r: 3 }}
                    activeDot={{ r: 5 }}
                    isAnimationActive={false}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
          <details className="chart-data">
            <summary>View chart data</summary>
            <table>
              <thead>
                <tr>
                  <th>Date</th>
                  <th>Scans</th>
                </tr>
              </thead>
              <tbody>
                {data.map((d) => (
                  <tr key={d.date}>
                    <td>{d.date}</td>
                    <td>{d.scans}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </details>
        </section>
        <section className="ec-panel coverage-panel">
          <div className="panel-heading">
            <div>
              <h2>Discovery coverage</h2>
              <p>Completed scans by type</p>
            </div>
          </div>
          {!severityChartData.length ? (
            <div className="chart-empty">
              <ShieldAlert size={28} />
              <strong>No findings to chart</strong>
              <p>Severity distribution appears after a completed scan records findings.</p>
            </div>
          ) : (
            <div className="grid items-center gap-3 sm:grid-cols-[minmax(0,1fr)_150px]">
              <div className="coverage-bars">
            {(
              [
                { kind: "network", label: "Network", Icon: Globe2 },
                { kind: "code", label: "Source code", Icon: Code2 },
                { kind: "binary", label: "Binary & firmware", Icon: Binary },
              ] as const
            ).map(({ kind, label, Icon }) => {
              const n = complete.filter((s) => s.kind === kind).length;
              return (
                <div key={kind}>
                  <div>
                    <Icon size={15} />
                    <span>{label}</span>
                    <strong>{n}</strong>
                  </div>
                  <div className="bar-track">
                    <span
                      style={{
                        width: `${complete.length ? (n / complete.length) * 100 : 0}%`,
                      }}
                    />
                  </div>
                </div>
              );
            })}
            <p>
              Scan counts show activity, not security coverage or readiness.
              Open each result to review skipped checks.
            </p>
              </div>
              <div className="h-[160px]" aria-label="Finding severity distribution">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityChartData} dataKey="value" nameKey="name" innerRadius={42} outerRadius={66} paddingAngle={3} isAnimationActive={false}>
                      {severityChartData.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: "var(--surface)", border: "1px solid var(--border)", color: "var(--text)", borderRadius: 8 }}
                    />
                    <Legend iconSize={8} wrapperStyle={{ fontSize: 10 }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </section>
      </div>
      <CorrelationGraph scans={scans} />
      <section className="ec-panel">
        <div className="panel-heading">
          <div>
            <h2>Recent discovery</h2>
            <p>Open a record to inspect its evidence</p>
          </div>
          <span className="count-label">{scans.length} saved records</span>
        </div>
        {!scans.length ? (
          <div className="empty-state">
            <strong>No scans yet</strong>
            <p>Choose a scan type below to get started.</p>
          </div>
        ) : (
          <div className="table-scroll">
            <table className="recent-table">
              <thead>
                <tr>
                  <th>Target / artifact</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>
                    <span className="sr-only">Action</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {scans.slice(0, 6).map((s) => (
                  <tr key={s.id}>
                    <td>
                      {s.result?.target ||
                        (s.result?.findings || s.result?.detections || [])[0]
                          ?.file ||
                        `${s.kind} scan · ${s.id.slice(0, 8)}`}
                    </td>
                    <td>{s.kind}</td>
                    <td>
                      <span className={`status-pill ${s.status}`}>
                        {s.status}
                      </span>
                    </td>
                    <td>{new Date(s.created_at).toLocaleDateString()}</td>
                    <td>
                      <button
                        className="ec-button secondary compact"
                        onClick={() => onInspect(s.id)}
                      >
                        Inspect <ArrowRight size={13} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <div className="quick-actions">
        {(
          [
            { kind: "network", title: "Website & TLS", Icon: Globe2 },
            { kind: "code", title: "Source code", Icon: Code2 },
            { kind: "binary", title: "Binary & firmware", Icon: Binary },
          ] as const
        ).map(({ kind, title, Icon }) => (
          <button
            key={kind}
            className="quick-action"
            onClick={() => onStart(kind)}
          >
            <Icon size={20} />
            <span>
              {title}
              <small>Start a real scan</small>
            </span>
            <ArrowRight size={16} />
          </button>
        ))}
        <button className="quick-action" onClick={onMigration}>
          <Route size={20} />
          <span>
            Migration planner<small>Security + hosting</small>
          </span>
          <ArrowRight size={16} />
        </button>
        {onVerification && (
          <button className="quick-action" onClick={onVerification}>
            <FileCheck2 size={20} />
            <span>
              Verification engine<small>Closed-loop audit</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
        {onStandards && (
          <button className="quick-action" onClick={onStandards}>
            <Scale size={20} />
            <span>
              Standards matrix<small>FIPS 203 / CNSA 2.0</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
        {onExperimental && (
          <button className="quick-action" onClick={onExperimental}>
            <FlaskConical size={20} />
            <span>
              Experimental hub<small>7 Next-gen tools</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
        {onSihDemo && (
          <button className="quick-action" onClick={onSihDemo}>
            <PlayCircle size={20} />
            <span>
              SIH 10-step demo<small>Judge walkthrough</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
        {onPatchMigration && (
          <button className="quick-action" onClick={onPatchMigration}>
            <Wrench size={20} className="text-emerald-400" />
            <span>
              Codebase Auto-Patcher<small>Full source ZIP upload</small>
            </span>
            <ArrowRight size={16} />
          </button>
        )}
      </div>
    </div>
  );
}
