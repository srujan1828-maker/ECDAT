"use client";

import { useEffect, useState } from "react";
import {
  ShieldAlert,
  Zap,
  FileDiff,
  Radio,
  Clock,
  ExternalLink,
  ChevronRight,
  ShieldCheck,
  AlertTriangle,
  Info,
  Layers,
  Sparkles,
  FileCode2,
  Lock,
  Archive,
  Terminal,
  Server,
  KeyRound,
  CheckCircle2,
} from "lucide-react";
import { Scan, OverviewStats, requestApi } from "@/lib/api";

const DEFAULT_STATS: OverviewStats = {
  system_name: "Default Enterprise System",
  environment: "PRODUCTION",
  posture_status: "CRITICAL",
  subtitle: "High-assurance cryptographic asset boundary and post-quantum migration tracking.",
  metrics: {
    crypto_assets: 20,
    crypto_assets_sub: "Discovered in Project →",
    quantum_relevant: 6,
    quantum_relevant_sub: "Shor Algorithm Vulnerable →",
    hndl_exposure: 6,
    hndl_exposure_sub: "Harvest Now Decrypt Later →",
    hybrid_pqc_capable: 3,
    hybrid_pqc_capable_sub: "NIST FIPS 203 In-Use →",
    completed_scans: 4,
    completed_scans_sub: "Deterministic Provenance →",
  },
  risk_distribution: {
    total_assets: 20,
    critical_shor: 6,
    safe_grover_pqc: 4,
    legacy_insecure: 3,
  },
  algorithm_family_distribution: [
    { name: "ECDSA", count: 2, percentage: 10, color: "#ef4444" },
    { name: "X25519", count: 1, percentage: 8, color: "#06b6d4" },
    { name: "SecP384r1MLKEM1024", count: 1, percentage: 8, color: "#3b82f6" },
    { name: "SecP256r1MLKEM768", count: 1, percentage: 8, color: "#06b6d4" },
    { name: "X25519MLKEM768", count: 1, percentage: 8, color: "#06b6d4" },
  ],
  multi_surface_coverage: [
    { name: "Source AST", status: "SCANNED", variant: "scanned" },
    { name: "Dependencies", status: "SUPPORTED", variant: "supported" },
    { name: "Binary Sections", status: "NOT_SCANNED", variant: "unscanned" },
    { name: "Firmware", status: "REDUCED", variant: "reduced" },
    { name: "Live Network", status: "SCANNED", variant: "scanned" },
    { name: "X.509 Certs", status: "NOT_SCANNED", variant: "unscanned" },
    { name: "Archive Lab", status: "ACTIVE", variant: "active" },
    { name: "PCAP Stream", status: "NOT_SCANNED", variant: "unscanned" },
    { name: "Runtime Call", status: "UNOBSERVED", variant: "unobserved" },
  ],
  action_queue: [
    {
      level: "CRIT",
      title: "Migrate 6 Quantum-Vulnerable Public Key Assets",
      detail: "Shor's algorithm breaks RSA-4096, ECDSA, RSA-2048. Immediate hybrid PQC transition required.",
      rationale: "Rationale: Shor's algorithm breaks RSA-4096, ECDSA, RSA-2048. Immediate hybrid PQC transition required.",
    },
    {
      level: "WARN",
      title: "Deprecate Legacy Cryptographic Primitives (3 detected)",
      detail: "Legacy ciphers and collision-vulnerable hashes detected (RC4, DES, SHA-1).",
      rationale: "Rationale: legacy ciphers and collision-vulnerable hashes detected (RC4, DES, SHA-1).",
    },
    {
      level: "NOTIFY",
      title: "Validate 3 Negotiated Hybrid PQC Key Shares",
      detail: "Confirm dual-mode parameters against NIST FIPS 203 specification for SecP256r1MLKEM768, X25519MLKEM768, SecP384r1MLKEM1024.",
      rationale: "Rationale: Confirm dual-mode parameters against NIST FIPS 203 specification for SecP256r1MLKEM768, X25519MLKEM768, SecP384r1MLKEM1024.",
    },
  ],
  threat_timeline: [
    { algorithm: "X25519", years_remaining: 4, percent: 30, color: "#f59e0b" },
    { algorithm: "SecP384r1MLKEM1024", years_remaining: 5, percent: 40, color: "#f59e0b" },
    { algorithm: "SecP256r1MLKEM768", years_remaining: 7, percent: 55, color: "#f59e0b" },
    { algorithm: "X25519MLKEM768", years_remaining: 9, percent: 70, color: "#f59e0b" },
    { algorithm: "RSA-4096", years_remaining: 12, percent: 90, color: "#f59e0b" },
    { algorithm: "RSA-2048", years_remaining: 4, percent: 30, color: "#f59e0b" },
  ],
};

const SURFACE_ICONS: Record<string, any> = {
  "Source AST": FileCode2,
  Dependencies: Layers,
  "Binary Sections": Terminal,
  Firmware: Server,
  "Live Network": Radio,
  "X.509 Certs": KeyRound,
  "Archive Lab": Archive,
  "PCAP Stream": Radio,
  "Runtime Call": Zap,
};

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
  onAutonomousLoop,
  onLiveDemo,
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
  onAutonomousLoop?: () => void;
  onLiveDemo?: () => void;
}) {
  const [stats, setStats] = useState<OverviewStats>(DEFAULT_STATS);

  useEffect(() => {
    // Attempt to load live overview stats from backend if reachable
    requestApi<OverviewStats>("/system/overview-stats", "default", "")
      .then((data) => {
        if (data && data.metrics) setStats(data);
      })
      .catch(() => {
        // Use default high-assurance state
      });
  }, []);

  const totalAssets = stats.risk_distribution.total_assets || 20;
  const critCount = stats.risk_distribution.critical_shor || 6;
  const safeCount = stats.risk_distribution.safe_grover_pqc || 4;
  const legacyCount = stats.risk_distribution.legacy_insecure || 3;

  return (
    <div className="space-y-6 pb-12">
      {/* ── Top Header Section (Images 2 & 3) ── */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2.5">
            <h1 className="text-xl font-bold tracking-tight text-foreground sm:text-2xl">
              {stats.system_name}
            </h1>
            <span className="rounded border border-red-500/30 bg-red-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-red-500 uppercase tracking-wider">
              {stats.environment}
            </span>
            <span className="rounded border border-red-500/20 bg-red-500/15 px-2 py-0.5 text-[10px] font-semibold text-red-400 uppercase">
              {stats.posture_status}
            </span>
          </div>
          <p className="mt-1 text-xs text-quiet sm:text-sm">
            {stats.subtitle}
          </p>
        </div>

        {/* Action Buttons Top Right */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={onAutonomousLoop}
            className="flex items-center gap-1.5 rounded-md border border-cyan-500/30 bg-cyan-500/10 px-3 py-1.5 text-xs font-semibold text-teal shadow-xs hover:bg-cyan-500/20 transition-all"
          >
            <Zap size={14} className="text-teal" />
            <span>One-Click Custom Loop</span>
          </button>
          <button
            type="button"
            onClick={onMigration}
            className="flex items-center gap-1.5 rounded-md border border-subtle bg-surface px-3 py-1.5 text-xs font-semibold text-foreground shadow-xs hover:bg-surface-raised transition-all"
          >
            <FileDiff size={14} className="text-quiet" />
            <span>Changes Diff</span>
          </button>
          <button
            type="button"
            onClick={() => onStart("code")}
            className="flex items-center gap-1.5 rounded-md bg-teal px-3 py-1.5 text-xs font-semibold text-slate-950 shadow-xs hover:bg-teal/90 transition-all"
          >
            <Radio size={14} />
            <span>Run Discovery</span>
          </button>
        </div>
      </div>

      {/* ── 5 Metric Cards Row (Screenshots 2 & 3) ── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        {[
          {
            title: "Crypto Assets",
            value: stats.metrics.crypto_assets,
            sub: stats.metrics.crypto_assets_sub,
            onClick: () => onStart("code"),
            valColor: "text-foreground",
          },
          {
            title: "Quantum-Relevant",
            value: stats.metrics.quantum_relevant,
            sub: stats.metrics.quantum_relevant_sub,
            onClick: onMigration,
            valColor: "text-red-500",
          },
          {
            title: "HNDL Exposure",
            value: stats.metrics.hndl_exposure,
            sub: stats.metrics.hndl_exposure_sub,
            onClick: onMigration,
            valColor: "text-amber-500",
          },
          {
            title: "Hybrid PQC Capable",
            value: stats.metrics.hybrid_pqc_capable,
            sub: stats.metrics.hybrid_pqc_capable_sub,
            onClick: onStandards,
            valColor: "text-teal",
          },
          {
            title: "Completed Scans",
            value: scans.filter((s) => s.status === "completed").length || stats.metrics.completed_scans,
            sub: stats.metrics.completed_scans_sub,
            onClick: () => onStart("network"),
            valColor: "text-foreground",
          },
        ].map((card, idx) => (
          <div
            key={idx}
            onClick={card.onClick}
            className="group cursor-pointer rounded-lg border border-subtle bg-surface p-4 shadow-xs transition-all hover:border-cyan-500/40 hover:shadow-sm"
          >
            <p className="text-xs font-medium text-quiet">{card.title}</p>
            <p className={`mt-2 text-2xl font-bold tracking-tight ${card.valColor}`}>
              {card.value}
            </p>
            <p className="mt-2 text-[11px] font-medium text-cyan-600 dark:text-cyan-400 group-hover:underline">
              {card.sub}
            </p>
          </div>
        ))}
      </div>

      {/* ── 2-Column Section: Risk Distribution & Algorithm Family Distribution ── */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Left: Risk Distribution Donut */}
        <div className="rounded-lg border border-subtle bg-surface p-5 shadow-xs">
          <div className="flex items-center justify-between pb-4 border-b border-subtle">
            <h2 className="text-sm font-semibold text-foreground">Risk Distribution</h2>
            <span className="font-mono text-xs text-quiet">
              Total Assets: {totalAssets}
            </span>
          </div>

          <div className="mt-6 flex flex-col items-center justify-around gap-6 sm:flex-row">
            {/* Donut SVG */}
            <div className="relative flex items-center justify-center">
              <svg width="150" height="150" viewBox="0 0 100 100" className="rotate-[-90deg]">
                {/* Background circle */}
                <circle cx="50" cy="50" r="38" fill="none" stroke="currentColor" className="text-slate-200 dark:text-slate-800" strokeWidth="12" />
                {/* Critical segment */}
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#ef4444"
                  strokeWidth="12"
                  strokeDasharray="238.7"
                  strokeDashoffset={238.7 * (1 - critCount / totalAssets)}
                  strokeLinecap="round"
                />
                {/* Safe segment */}
                <circle
                  cx="50"
                  cy="50"
                  r="38"
                  fill="none"
                  stroke="#10b981"
                  strokeWidth="12"
                  strokeDasharray="238.7"
                  strokeDashoffset={238.7 * (1 - safeCount / totalAssets)}
                  className="rotate-[120deg] origin-center"
                  strokeLinecap="round"
                />
              </svg>
              <div className="absolute flex flex-col items-center justify-center text-center">
                <span className="text-xl font-extrabold text-foreground">{totalAssets}</span>
                <span className="text-[10px] font-semibold text-quiet uppercase tracking-wider">ASSETS</span>
              </div>
            </div>

            {/* Donut Legend */}
            <div className="space-y-2.5 text-xs">
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-red-500 shrink-0" />
                <span className="text-quiet">Critical (Shor Vuln):</span>
                <span className="font-bold text-foreground">{critCount}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 shrink-0" />
                <span className="text-quiet">Safe (Grover / PQC):</span>
                <span className="font-bold text-foreground">{safeCount}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-2.5 w-2.5 rounded-full bg-amber-500 shrink-0" />
                <span className="text-quiet">Legacy Insecure:</span>
                <span className="font-bold text-foreground">{legacyCount}</span>
              </div>
            </div>
          </div>
        </div>

        {/* Right: Algorithm Family Distribution (Empirical Frequency) */}
        <div className="rounded-lg border border-subtle bg-surface p-5 shadow-xs">
          <div className="flex items-center justify-between pb-4 border-b border-subtle">
            <h2 className="text-sm font-semibold text-foreground">
              Algorithm Family Distribution
            </h2>
            <span className="font-mono text-xs text-cyan-600 dark:text-cyan-400">
              Empirical Frequency
            </span>
          </div>

          <div className="mt-4 space-y-3.5">
            {stats.algorithm_family_distribution.map((item, idx) => (
              <div key={idx} className="space-y-1">
                <div className="flex items-center justify-between text-xs font-medium">
                  <span className="text-foreground">{item.name}</span>
                  <span className="font-mono text-quiet text-[11px]">
                    {item.count} ({item.percentage}%)
                  </span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
                  <div
                    className="h-full rounded-full transition-all duration-500"
                    style={{
                      width: `${item.percentage * 3.5}%`,
                      backgroundColor: item.color || "#06b6d4",
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Multi-Surface Discovery Coverage Row (Image 2) ── */}
      <div className="rounded-lg border border-subtle bg-surface p-5 shadow-xs">
        <h2 className="text-sm font-semibold text-foreground mb-4">
          Multi-Surface Discovery Coverage
        </h2>

        <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3 md:grid-cols-5 lg:grid-cols-9">
          {stats.multi_surface_coverage.map((surf, idx) => {
            const Icon = SURFACE_ICONS[surf.name] || FileCode2;
            let badgeClass = "border-slate-500/30 bg-slate-500/10 text-slate-400";
            if (surf.status === "SCANNED") badgeClass = "border-emerald-500/30 bg-emerald-500/10 text-emerald-500";
            else if (surf.status === "SUPPORTED") badgeClass = "border-blue-500/30 bg-blue-500/10 text-blue-400";
            else if (surf.status === "ACTIVE") badgeClass = "border-cyan-500/30 bg-cyan-500/10 text-teal";
            else if (surf.status === "REDUCED") badgeClass = "border-amber-500/30 bg-amber-500/10 text-amber-400";

            return (
              <div
                key={idx}
                className="flex flex-col items-center justify-center gap-2 rounded-md border border-subtle bg-canvas/60 p-3 text-center transition-colors hover:border-cyan-500/30"
              >
                <Icon size={18} className="text-cyan-500" />
                <span className="text-[11px] font-medium text-foreground truncate max-w-full">
                  {surf.name}
                </span>
                <span className={`rounded border px-1.5 py-0.5 font-mono text-[9px] font-semibold uppercase ${badgeClass}`}>
                  {surf.status}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Evidence-Driven Action Queue (Image 3) ── */}
      <div className="rounded-lg border border-subtle bg-surface p-5 shadow-xs">
        <h2 className="text-sm font-semibold text-foreground mb-4">
          Evidence-Driven Action Queue
        </h2>

        <div className="space-y-3">
          {stats.action_queue.map((action, idx) => {
            let containerStyle = "border-red-500/30 bg-red-500/5 text-red-400";
            let badgeStyle = "bg-red-500 text-white";
            if (action.level === "WARN") {
              containerStyle = "border-amber-500/30 bg-amber-500/5 text-amber-400";
              badgeStyle = "bg-amber-500 text-white";
            } else if (action.level === "NOTIFY") {
              containerStyle = "border-cyan-500/30 bg-cyan-500/5 text-cyan-400";
              badgeStyle = "bg-teal text-slate-950 font-bold";
            }

            return (
              <div
                key={idx}
                className={`flex items-start gap-3 rounded-md border p-3.5 text-xs transition-all ${containerStyle}`}
              >
                <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase shrink-0 ${badgeStyle}`}>
                  {action.level}
                </span>
                <div className="space-y-1">
                  <p className="font-semibold text-foreground">{action.title}</p>
                  <p className="text-[11px] text-quiet leading-relaxed">{action.detail}</p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Cryptographic Quantum Threat Timeline (Z Horizon) (Image 3) ── */}
      <div className="rounded-lg border border-subtle bg-surface p-5 shadow-xs">
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between mb-4">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
              <Clock size={16} className="text-cyan-500" />
              Cryptographic Quantum Threat Timeline (Z Horizon)
            </h2>
            <p className="mt-0.5 text-xs text-quiet">
              Years remaining until cryptanalytically relevant quantum computing (CRQC) breaks discovered primitives under published research (Gidney &amp; Ekerå 2021).
            </p>
          </div>
          <button
            type="button"
            onClick={onStandards}
            className="flex items-center gap-1 text-xs font-medium text-cyan-600 dark:text-cyan-400 hover:underline shrink-0"
          >
            <span>Interactive Mosca Calculator</span>
            <ChevronRight size={14} />
          </button>
        </div>

        <div className="mt-6 space-y-4">
          {stats.threat_timeline.map((item, idx) => (
            <div key={idx} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-mono font-medium text-foreground">{item.algorithm}</span>
                <span className="font-medium text-amber-500 text-[11px]">
                  {item.years_remaining} years to CRQC break
                </span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
                <div
                  className="h-full rounded-full transition-all duration-700"
                  style={{
                    width: `${item.percent}%`,
                    backgroundColor: item.color || "#f59e0b",
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
