"use client";
import { useMemo, useState } from "react";
import {
  Area,
  AreaChart,
  CartesianGrid,
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
  BookOpen,
  Route,
  X,
} from "lucide-react";
import { Scan } from "@/lib/api";
export function Overview({
  scans,
  connected,
  onStart,
  onInspect,
  onMigration,
}: {
  scans: Scan[];
  connected: boolean;
  onStart: (kind: "network" | "code" | "binary") => void;
  onInspect: (id: string) => void;
  onMigration: () => void;
}) {
  const [tips, setTips] = useState(true);
  const [days, setDays] = useState(7);
  const complete = scans.filter((s) => s.status === "completed");
  const active = scans.filter((s) => ["queued", "running"].includes(s.status));
  const findings = complete.flatMap(
    (s) => s.result?.findings || s.result?.detections || [],
  );
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
      {tips ? (
        <section className="starting-tips">
          <div className="tips-title">
            <BookOpen size={18} />
            <strong>Your first scan, in three steps</strong>
            <button
              onClick={() => setTips(false)}
              aria-label="Hide starting tips"
            >
              <X size={16} />
            </button>
          </div>
          <div className="tips-grid">
            {[
              ["01", "Choose a target", "Start with a website you own."],
              [
                "02",
                "Review the evidence",
                "Check findings and scan coverage.",
              ],
              ["03", "Plan your next move", "Add context and build a roadmap."],
            ].map(([n, t, d]) => (
              <div key={n}>
                <span>{n}</span>
                <p>
                  <strong>{t}</strong>
                  <small>{d}</small>
                </p>
              </div>
            ))}
          </div>
        </section>
      ) : (
        <button className="text-action" onClick={() => setTips(true)}>
          <BookOpen size={14} /> Show starting tips
        </button>
      )}
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
                <AreaChart
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
                  <Area
                    dataKey="scans"
                    name="Scans submitted"
                    type="linear"
                    stroke="var(--teal)"
                    strokeWidth={2}
                    fill="var(--teal)"
                    fillOpacity={0.12}
                    isAnimationActive={false}
                  />
                </AreaChart>
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
        </section>
      </div>
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
      </div>
    </div>
  );
}
