"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import dynamic from "next/dynamic";
import {
  fetchOverview, scanNetwork, scanCode,
  evaluateMosca, exportCbom,
} from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Slider } from "@/components/ui/slider";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Shield, ShieldAlert, Activity, Code, Globe, FileKey,
  CheckCircle2, ChevronDown, Download, Server, RefreshCcw,
  AlertTriangle, Database, Network, Lock, TrendingUp,
  Zap, BookOpen, ChevronRight, XCircle,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

// ─── Force Graph (SSR-safe) ───────────────────────────────────────────────────
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), { ssr: false });

// ─── Types ────────────────────────────────────────────────────────────────────

interface KPIs {
  total_findings: number;
  critical: number;
  quantum_vulnerable_certs: number;
  est_migration_effort: string;
}

interface GraphNode {
  id: string;
  label: string;
  group: string;
  severity: string;
  blast_radius?: string[];
}

interface GraphLink { source: string; target: string; label?: string; }
interface OverviewData { kpis: KPIs; graph: { nodes: GraphNode[]; links: GraphLink[] }; }

interface Finding {
  line: number;
  code: string;
  primitive: string;
  category: string;
  severity: string;
  issue: string;
  nist_recommendation: string;
  quantum_risk: string;
}

interface NistMapping {
  category: string;
  legacy_primitive: string;
  quantum_threat: string;
  pqc_standard: string;
  security_levels: string;
  urgency: string;
}

interface MoscaResult {
  is_critical: boolean;
  posture_status: string;
  explanation: string;
  deficit_years: number;
  total_time_needed: number;
  x_shelf_life: number;
  y_migration_time: number;
  z_crqc_horizon: number;
  nist_mapping?: NistMapping[];
}

// ─── Design tokens ────────────────────────────────────────────────────────────

const C = {
  canvas:   "bg-[var(--ecdat-canvas)]",
  surface:  "bg-[var(--ecdat-surface)]",
  raised:   "bg-[var(--ecdat-surface-raised)]",
  border:   "border-[var(--ecdat-border-subtle)]",
} as const;

const sevBadge = (s: string) => {
  const l = (s ?? "").toLowerCase();
  if (l === "critical") return "bg-red-500/10 text-red-400 border border-red-500/20";
  if (l === "high")     return "bg-amber-500/10 text-amber-400 border border-amber-500/20";
  if (l === "medium")   return "bg-yellow-400/10 text-yellow-400 border border-yellow-400/20";
  return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
};

const sevNodeColor = (s: string) => {
  const l = (s ?? "").toLowerCase();
  if (l === "critical") return "#ef4444";
  if (l === "high")     return "#f59e0b";
  if (l === "medium")   return "#facc15";
  return "#10b981";
};

const urgencyBadge = (u: string) => {
  if (u === "IMMEDIATE") return "bg-red-500/10 text-red-400 border border-red-500/20";
  if (u === "HIGH")      return "bg-amber-500/10 text-amber-400 border border-amber-500/20";
  if (u === "MEDIUM")    return "bg-yellow-400/10 text-yellow-400 border border-yellow-400/20";
  return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
};

// ─── KPI Card ─────────────────────────────────────────────────────────────────

function KpiCard({
  label, value, sub, valueClass = "text-slate-100",
  icon: Icon, accent,
}: {
  label: string; value: string | number; sub?: string;
  valueClass?: string; icon: React.ElementType; accent: string;
}) {
  return (
    <Card className={`${C.surface} ${C.border} overflow-hidden`}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between mb-3">
          <div className={`w-9 h-9 rounded-lg flex items-center justify-center ${accent}`}>
            <Icon className="w-4 h-4" />
          </div>
        </div>
        <p className={`text-3xl font-bold font-mono tracking-tight ${valueClass}`}>{value}</p>
        <p className="text-xs font-medium text-slate-400 mt-1.5 uppercase tracking-widest">{label}</p>
        {sub && <p className="text-[11px] text-slate-600 mt-1">{sub}</p>}
      </CardContent>
    </Card>
  );
}

// ─── Divider ──────────────────────────────────────────────────────────────────
const Divider = () => <div className={`border-t ${C.border}`} />;

// ─── Known targets ────────────────────────────────────────────────────────────
const KNOWN_TARGETS = [
  { domain: "rc4.badssl.com",            note: "RC4 stream cipher — deprecated RFC 7465" },
  { domain: "expired.badssl.com",        note: "Expired X.509 certificate" },
  { domain: "null.badssl.com",           note: "NULL cipher — no encryption" },
  { domain: "tls-v1-0.badssl.com:1010",  note: "TLS 1.0 — POODLE vulnerable" },
  { domain: "sha1-intermediate.badssl.com", note: "SHA-1 intermediate cert" },
];

// ─── Nav items ────────────────────────────────────────────────────────────────
const NAV = [
  { id: "overview", label: "Overview",       icon: Activity,    desc: "Posture summary" },
  { id: "network",  label: "Network Prober", icon: Globe,       desc: "TLS inspection" },
  { id: "code",     label: "Code Scanner",   icon: Code,        desc: "AST analysis" },
  { id: "risk",     label: "Risk & CBOM",    icon: ShieldAlert, desc: "Mosca engine" },
];

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

export default function ECDATDashboard() {
  // ── Core state ──────────────────────────────────────────────────────────────
  const [activeTab, setActiveTab] = useState("overview");
  const graphRef  = useRef<HTMLDivElement>(null);
  const [graphW,  setGraphW]  = useState(900);

  useEffect(() => {
    const el = graphRef.current;
    if (!el) return;
    const ro = new ResizeObserver(([e]) => setGraphW(e.contentRect.width));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // ── Overview ────────────────────────────────────────────────────────────────
  const [lastScan,      setLastScan]      = useState<string | null>(null);
  const [overview,      setOverview]      = useState<OverviewData | null>(null);
  const [ovLoading,     setOvLoading]     = useState(true);
  const [selectedNode,  setSelectedNode]  = useState<GraphNode | null>(null);

  const loadOverview = useCallback(async () => {
    setOvLoading(true);
    const r = await fetchOverview();
    if (r.data) setOverview(r.data);
    setOvLoading(false);
  }, []);

  // ── Network ─────────────────────────────────────────────────────────────────
  const [netTarget,  setNetTarget]  = useState("rc4.badssl.com");
  const [netOpen,    setNetOpen]    = useState(false);
  const [netLoading, setNetLoading] = useState(false);
  const [netResult,  setNetResult]  = useState<any>(null);

  const runNetworkScan = async () => {
    setNetLoading(true);
    setNetResult(null);
    const [host, portStr] = netTarget.split(":");
    const r = await scanNetwork(host, portStr ? parseInt(portStr) : 443);
    setNetResult(r.data);
    setNetLoading(false);
    setLastScan(new Date().toLocaleTimeString());
    loadOverview();
  };

  // ── Code ────────────────────────────────────────────────────────────────────
  const SAMPLE_CODE = `# Python code to audit — edit or paste your own
import hashlib
from cryptography.hazmat.primitives.ciphers import algorithms
import rsa

def insecure_auth(password: str) -> str:
    # CWE-327: Use of a broken or risky cryptographic algorithm
    return hashlib.md5(password.encode()).hexdigest()

def legacy_encrypt(key: bytes, data: bytes):
    # CWE-326: Inadequate encryption strength (DES = 56-bit)
    return algorithms.DES(key)

def gen_rsa_keypair():
    # Quantum threat: Shor's algorithm (NIST deprecates RSA < 2048)
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)
`;
  const [sourceCode,    setSourceCode]    = useState(SAMPLE_CODE);
  const [codeLoading,   setCodeLoading]   = useState(false);
  const [findings,      setFindings]      = useState<Finding[]>([]);
  const [remediation,   setRemediation]   = useState("");
  const [selFinding,    setSelFinding]    = useState<Finding | null>(null);
  const [codeScanned,   setCodeScanned]   = useState(false);

  const runCodeScan = async () => {
    setCodeLoading(true);
    setSelFinding(null);
    const r = await scanCode(sourceCode);
    if (r.data) {
      setFindings(r.data.findings ?? []);
      setRemediation(r.data.remediation ?? "");
      setCodeScanned(true);
      loadOverview();
    }
    setCodeLoading(false);
    setLastScan(new Date().toLocaleTimeString());
  };

  // ── Risk ────────────────────────────────────────────────────────────────────
  const [x, setX] = useState([10]);
  const [y, setY] = useState([4]);
  const [z, setZ] = useState([8]);
  const [mosca,       setMosca]       = useState<MoscaResult | null>(null);
  const [moscaLoading, setMoscaLoading] = useState(false);

  const runMosca = async () => {
    setMoscaLoading(true);
    const r = await evaluateMosca(x[0], y[0], z[0]);
    if (r.data) setMosca(r.data);
    setMoscaLoading(false);
  };

  const downloadCbom = async () => {
    const r = await exportCbom(findings, netResult ? [netResult] : [], "ECDAT-SIH26164-NTRO");
    const blob = new Blob([JSON.stringify(r.data ?? {}, null, 2)], { type: "application/json" });
    const url  = URL.createObjectURL(blob);
    const a    = Object.assign(document.createElement("a"), { href: url, download: "ecdat_cbom_cyclonedx_v1.6.json" });
    document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
  };

  // ── Bootstrap ───────────────────────────────────────────────────────────────
  useEffect(() => {
    loadOverview();
    runMosca();
    runCodeScan();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ────────────────────────────────────────────────────────────────────────────
  //  RENDER
  // ────────────────────────────────────────────────────────────────────────────
  return (
    <div className={`flex h-screen overflow-hidden ${C.canvas} text-slate-100 font-sans`}>

      {/* ═════════════════ SIDEBAR ═════════════════ */}
      <aside className={`w-56 shrink-0 flex flex-col ${C.surface} border-r ${C.border}`}>

        {/* Brand */}
        <div className={`p-5 flex items-center gap-3 border-b ${C.border}`}>
          <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/25 flex items-center justify-center shrink-0">
            <Shield className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-bold tracking-tight text-slate-100 leading-none">ECDAT</p>
            <p className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">SIH26164 · NTRO</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-2.5 space-y-0.5 overflow-y-auto">
          {NAV.map(({ id, label, icon: Icon, desc }) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-md text-left transition-all group ${
                  active
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/15"
                    : `text-slate-400 hover:text-slate-200 hover:${C.raised} border border-transparent`
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${active ? "text-cyan-400" : "text-slate-500 group-hover:text-slate-300"}`} />
                <div className="min-w-0">
                  <p className="text-xs font-semibold leading-none truncate">{label}</p>
                  <p className={`text-[10px] mt-0.5 truncate ${active ? "text-cyan-500/70" : "text-slate-600"}`}>{desc}</p>
                </div>
                {active && <ChevronRight className="w-3 h-3 ml-auto shrink-0 text-cyan-500/50" />}
              </button>
            );
          })}
        </nav>

        {/* Live metrics strip */}
        <div className={`p-3 border-t ${C.border}`}>
          <p className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest mb-2 px-1">Live Metrics</p>
          <div className={`rounded-md ${C.raised} border ${C.border} divide-y divide-[var(--ecdat-border-subtle)]`}>
            {[
              { label: "Findings",   val: overview?.kpis.total_findings,              cls: "text-slate-300" },
              { label: "Critical",   val: overview?.kpis.critical,                    cls: "text-red-400"   },
              { label: "QV Certs",   val: overview?.kpis.quantum_vulnerable_certs,    cls: "text-amber-400" },
            ].map(({ label, val, cls }) => (
              <div key={label} className="flex items-center justify-between px-3 py-2 text-[11px] font-mono">
                <span className="text-slate-500">{label}</span>
                <span className={`font-semibold ${cls}`}>{ovLoading ? "…" : (val ?? "—")}</span>
              </div>
            ))}
          </div>
          {lastScan && (
            <p className="text-[10px] text-slate-600 font-mono mt-2 flex items-center gap-1.5 px-1">
              <Activity className="w-3 h-3" />
              Last scan {lastScan}
            </p>
          )}
        </div>
      </aside>

      {/* ═════════════════ MAIN ═════════════════ */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {/* Topbar */}
        <header className={`h-14 shrink-0 flex items-center justify-between px-6 border-b ${C.border} ${C.canvas} backdrop-blur-sm`}>
          <div className="flex items-center gap-3">
            {(() => {
              const n = NAV.find(i => i.id === activeTab)!;
              const Icon = n.icon;
              return (
                <>
                  <Icon className="w-4 h-4 text-slate-400" />
                  <div>
                    <h1 className="text-sm font-semibold text-slate-100 leading-none">{n.label}</h1>
                    <p className="text-[10px] text-slate-500 mt-0.5">{n.desc}</p>
                  </div>
                </>
              );
            })()}
          </div>

          <div className="flex items-center gap-2">
            <Badge className="font-mono text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 gap-1 py-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse inline-block" />
              LIVE ENGINE
            </Badge>
            <Badge className="font-mono text-[10px] bg-slate-500/10 text-slate-400 border border-slate-500/20 py-0.5">
              NTRO · SIH26164
            </Badge>
          </div>
        </header>

        {/* Scrollable content */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-6">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.14, ease: "easeOut" }}
              >

                {/* ══════════════════════════════════════════
                    OVERVIEW
                    ══════════════════════════════════════════ */}
                {activeTab === "overview" && (
                  <div className="space-y-5">

                    {/* KPIs */}
                    {ovLoading ? (
                      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
                        {[0,1,2,3].map(i => (
                          <Skeleton key={i} className={`h-28 ${C.raised} rounded-xl`} />
                        ))}
                      </div>
                    ) : overview?.kpis && (
                      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
                        <KpiCard
                          label="Total Findings"    value={overview.kpis.total_findings}
                          icon={Database}           accent="bg-cyan-500/10 text-cyan-400"
                        />
                        <KpiCard
                          label="Critical Risks"   value={overview.kpis.critical}
                          valueClass="text-red-400"  icon={ShieldAlert}
                          accent="bg-red-500/10 text-red-400"
                        />
                        <KpiCard
                          label="QV Certificates"  value={overview.kpis.quantum_vulnerable_certs}
                          valueClass="text-amber-400" icon={Lock}
                          accent="bg-amber-500/10 text-amber-400"
                          sub="Quantum-vulnerable assets"
                        />
                        <KpiCard
                          label="Est. Migration"   value={overview.kpis.est_migration_effort}
                          icon={TrendingUp}         accent="bg-emerald-500/10 text-emerald-400"
                        />
                      </div>
                    )}

                    {/* Graph */}
                    <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                      <CardHeader className={`border-b ${C.border} py-4`}>
                        <div className="flex items-center justify-between gap-4">
                          <div>
                            <CardTitle className="text-sm font-semibold text-slate-200">
                              Cryptographic Dependency Graph
                            </CardTitle>
                            <CardDescription className="text-slate-500 text-xs mt-0.5">
                              Live view of Service → Library → Algorithm → Certificate relationships. Click a node for blast-radius analysis.
                            </CardDescription>
                          </div>
                          <div className="flex items-center gap-4 shrink-0">
                            {[["Critical","#ef4444"],["High","#f59e0b"],["Medium","#facc15"],["Low","#10b981"]].map(([l, c]) => (
                              <div key={l} className="flex items-center gap-1.5 text-[11px] text-slate-500 font-mono">
                                <div className="w-2 h-2 rounded-full" style={{ background: c }} />
                                {l}
                              </div>
                            ))}
                          </div>
                        </div>
                      </CardHeader>
                      <div ref={graphRef} className={`w-full h-[480px] ${C.canvas}`}>
                        {overview?.graph ? (
                          <ForceGraph2D
                            graphData={overview.graph}
                            width={graphW}
                            height={480}
                            backgroundColor="transparent"
                            nodeRelSize={6}
                            linkColor={() => "#1e293b"}
                            linkWidth={1.5}
                            linkDirectionalArrowLength={4}
                            linkDirectionalArrowRelPos={1}
                            onNodeClick={(n) => setSelectedNode(n as GraphNode)}
                            nodeCanvasObject={(node: any, ctx, scale) => {
                              // Guard: skip until force-graph assigns finite coordinates
                              if (!isFinite(node.x) || !isFinite(node.y)) return;
                              const r = 7;
                              const color = sevNodeColor(node.severity);
                              // Soft glow
                              const grad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 2.5);
                              grad.addColorStop(0, color + "44");
                              grad.addColorStop(1, color + "00");
                              ctx.beginPath();
                              ctx.arc(node.x, node.y, r * 2.5, 0, Math.PI * 2);
                              ctx.fillStyle = grad;
                              ctx.fill();
                              // Filled circle
                              ctx.beginPath();
                              ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
                              ctx.fillStyle = color;
                              ctx.fill();
                              ctx.strokeStyle = "rgba(255,255,255,0.18)";
                              ctx.lineWidth = 1;
                              ctx.stroke();
                              // Label
                              const fs = Math.max(9, 11 / scale);
                              ctx.font = `500 ${fs}px Inter, sans-serif`;
                              ctx.fillStyle = "#94a3b8";
                              ctx.textAlign = "center";
                              ctx.fillText(node.label ?? "", node.x, node.y + r + fs + 2);
                            }}
                          />
                        ) : (
                          <div className="flex flex-col items-center justify-center h-full gap-3">
                            {ovLoading ? (
                              <>
                                <RefreshCcw className="w-5 h-5 text-slate-600 animate-spin" />
                                <p className="text-sm text-slate-600">Building knowledge graph…</p>
                              </>
                            ) : (
                              <>
                                <Network className="w-8 h-8 text-slate-700" />
                                <p className="text-sm text-slate-600">No graph data available.</p>
                              </>
                            )}
                          </div>
                        )}
                      </div>
                    </Card>

                    {/* Blast-radius dialog */}
                    <Dialog open={!!selectedNode} onOpenChange={() => setSelectedNode(null)}>
                      <DialogContent className={`${C.surface} ${C.border} text-slate-100 max-w-md`}>
                        <DialogHeader>
                          <div className="flex items-start justify-between gap-3">
                            <DialogTitle className="font-mono text-base leading-tight">{selectedNode?.label}</DialogTitle>
                            {selectedNode && (
                              <Badge className={`${sevBadge(selectedNode.severity)} text-[10px] shrink-0 mt-0.5`}>
                                {selectedNode.severity?.toUpperCase()}
                              </Badge>
                            )}
                          </div>
                          <DialogDescription className="text-slate-500 text-xs">
                            Type: <span className="text-cyan-400 font-mono">{selectedNode?.group?.toUpperCase()}</span>
                          </DialogDescription>
                        </DialogHeader>
                        {selectedNode && (
                          <div className="space-y-3 pt-1">
                            <Divider />
                            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-medium">Computed Blast Radius</p>
                            {(selectedNode.blast_radius?.length ?? 0) > 0 ? (
                              <div className="space-y-1.5">
                                {selectedNode.blast_radius!.map((s, i) => (
                                  <div key={i} className={`flex items-center gap-2.5 text-xs font-mono text-slate-300 px-3 py-2 rounded-md ${C.raised} border ${C.border}`}>
                                    <div className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
                                    {s}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-sm text-slate-500 italic">Leaf node — no upstream dependencies. Minimal blast radius.</p>
                            )}
                          </div>
                        )}
                      </DialogContent>
                    </Dialog>
                  </div>
                )}

                {/* ══════════════════════════════════════════
                    NETWORK PROBER
                    ══════════════════════════════════════════ */}
                {activeTab === "network" && (
                  <div className="space-y-5">

                    {/* Control card */}
                    <Card className={`${C.surface} ${C.border}`}>
                      <CardHeader className={`border-b ${C.border} py-4`}>
                        <CardTitle className="text-sm font-semibold flex items-center gap-2 text-slate-200">
                          <Network className="w-4 h-4 text-cyan-400" />
                          TLS Endpoint Inspector
                        </CardTitle>
                        <CardDescription className="text-slate-500 text-xs">
                          Performs a non-intrusive TLS handshake to enumerate protocol version, cipher suite, and certificate metadata. Flags HNDL-vulnerable configurations.
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="py-4">
                        <div className="flex flex-wrap items-center gap-3">
                          <Popover open={netOpen} onOpenChange={setNetOpen}>
                            <PopoverTrigger className={`flex items-center justify-between gap-2 min-w-[240px] px-3 py-2 rounded-md border ${C.border} ${C.raised} text-sm font-mono text-slate-300 hover:border-slate-500 transition-colors focus:outline-none focus:border-cyan-500/50`}>
                              <span className="truncate">{netTarget || "Select target…"}</span>
                              <ChevronDown className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                            </PopoverTrigger>
                            <PopoverContent className={`w-[360px] p-0 ${C.surface} ${C.border}`}>
                              <Command className="bg-transparent">
                                <CommandInput
                                  placeholder="Search or type a domain…"
                                  className={`text-sm text-slate-200 border-b ${C.border}`}
                                  onValueChange={(v) => { if (v.length > 3 && v.includes(".")) setNetTarget(v); }}
                                />
                                <CommandList>
                                  <CommandEmpty className="text-slate-500 text-sm p-4">No results. Type a domain name.</CommandEmpty>
                                  <CommandGroup heading="Known Vulnerable Targets">
                                    {KNOWN_TARGETS.map(({ domain, note }) => (
                                      <CommandItem
                                        key={domain}
                                        value={domain}
                                        onSelect={(v) => { setNetTarget(v); setNetOpen(false); }}
                                        className="flex items-center justify-between gap-2 py-2 cursor-pointer"
                                      >
                                        <span className="font-mono text-xs text-slate-200">{domain}</span>
                                        <span className="text-[10px] text-slate-500 shrink-0">{note}</span>
                                      </CommandItem>
                                    ))}
                                  </CommandGroup>
                                </CommandList>
                              </Command>
                            </PopoverContent>
                          </Popover>

                          <Button
                            onClick={runNetworkScan}
                            disabled={netLoading || !netTarget}
                            className="bg-cyan-600 hover:bg-cyan-500 text-white shadow-none font-medium text-sm"
                          >
                            {netLoading ? (
                              <><RefreshCcw className="w-3.5 h-3.5 mr-2 animate-spin" />Probing…</>
                            ) : (
                              <><Activity className="w-3.5 h-3.5 mr-2" />Probe Endpoint</>
                            )}
                          </Button>

                          {netResult && (
                            <button
                              onClick={() => setNetResult(null)}
                              className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                            >
                              <XCircle className="w-3.5 h-3.5" /> Clear
                            </button>
                          )}
                        </div>

                        {/* Hint */}
                        {!netResult && !netLoading && (
                          <p className="text-xs text-slate-600 mt-3 pl-1">
                            Select from known-vulnerable targets or type any hostname. Results appear below.
                          </p>
                        )}

                        {/* Errors */}
                        {(netResult?.error || netResult?.status === "error") && (
                          <Alert className="mt-4 bg-red-500/8 border-red-500/20 text-red-400">
                            <AlertTriangle className="h-3.5 w-3.5" />
                            <AlertTitle className="text-xs font-semibold">Connection Failed</AlertTitle>
                            <AlertDescription className="font-mono text-[11px] mt-1">
                              {netResult.error ?? netResult.message ?? "Unknown error"}
                            </AlertDescription>
                          </Alert>
                        )}
                      </CardContent>
                    </Card>

                    {/* Results */}
                    {netResult && !netResult.error && netResult.status !== "error" && (
                      <motion.div
                        initial={{ opacity: 0, y: 8 }}
                        animate={{ opacity: 1, y: 0 }}
                        className="space-y-4"
                      >
                        {/* Row 1: Four Cryptographic Dimension Cards */}
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                          {/* 1. Protocol */}
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">Protocol</span>
                                <Server className="w-3.5 h-3.5 text-slate-600" />
                              </div>
                              <p className="text-xl font-bold font-mono text-slate-100">{netResult.protocol}</p>
                              <p className="text-[11px] text-slate-500 font-mono truncate">{netResult.target} ({netResult.ip_address})</p>
                            </CardContent>
                          </Card>

                          {/* 2. Cipher Suite */}
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">Bulk Cipher</span>
                                <FileKey className="w-3.5 h-3.5 text-slate-600" />
                              </div>
                              <p className="text-base font-bold font-mono text-slate-100 truncate">{netResult.bulk_cipher || netResult.cipher_name}</p>
                              <p className="text-[11px] text-cyan-400 font-mono truncate">{netResult.symmetric_security || `${netResult.secret_bits} bits`}</p>
                            </CardContent>
                          </Card>

                          {/* 3. Key Exchange (KEX) */}
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">Key Exchange (KEX)</span>
                                <Lock className="w-3.5 h-3.5 text-slate-600" />
                              </div>
                              <p className="text-xs font-bold font-mono text-slate-100 leading-snug break-words">
                                {netResult.key_exchange || "Standard Ephemeral"}
                              </p>
                              <p className="text-[11px] text-slate-500">
                                {netResult.key_exchange?.includes("No Forward Secrecy") ? (
                                  <span className="text-red-400 font-semibold">No Forward Secrecy</span>
                                ) : (
                                  <span className="text-emerald-400">Perfect Forward Secrecy Active</span>
                                )}
                              </p>
                            </CardContent>
                          </Card>

                          {/* 4. PQC / Hybrid Status */}
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold">PQC / Hybrid Status</span>
                                <Zap className="w-3.5 h-3.5 text-amber-400" />
                              </div>
                              <p className="text-xs font-bold font-mono text-slate-100 leading-snug">
                                {netResult.pqc_status || "Classical Ephemeral"}
                              </p>
                              <p className="text-[11px] text-slate-500">
                                {netResult.pqc_status?.includes("PQC-Hybrid") ? (
                                  <span className="text-emerald-400">Quantum Resistant KEX</span>
                                ) : netResult.pqc_status?.includes("Zero") || netResult.pqc_status?.includes("Insecure") ? (
                                  <span className="text-red-400">Zero Quantum Margin</span>
                                ) : (
                                  <span className="text-amber-400">Transition to ML-KEM Pending</span>
                                )}
                              </p>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Row 2: Certificate Parameters & Derived HNDL Exposure Analysis */}
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                          {/* Certificate Parameters Card */}
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardHeader className={`border-b ${C.border} py-3`}>
                              <div className="flex items-center justify-between">
                                <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                                  {netResult.certificate?.expired ? (
                                    <XCircle className="w-3.5 h-3.5 text-red-400" />
                                  ) : (
                                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                                  )}
                                  X.509 Certificate Parameters
                                </CardTitle>
                                <span className="font-mono text-xs text-slate-300">
                                  {Math.max(0, netResult.certificate?.days_remaining ?? 0)} days remaining
                                </span>
                              </div>
                            </CardHeader>
                            <CardContent className="p-4 space-y-3">
                              <div className="space-y-1.5">
                                <div className="flex justify-between text-xs font-mono">
                                  <span className="text-slate-500">Validity Expiry</span>
                                  <span className={netResult.certificate?.expired ? "text-red-400" : "text-emerald-400"}>
                                    {netResult.certificate?.valid_to || "N/A"}
                                  </span>
                                </div>
                                <div className={`w-full h-1.5 rounded-full ${C.raised} overflow-hidden`}>
                                  <div
                                    className={`h-full rounded-full ${netResult.certificate?.expired ? "bg-red-500" : "bg-emerald-500"}`}
                                    style={{ width: `${Math.min(100, Math.max(2, ((netResult.certificate?.days_remaining ?? 0) / 365) * 100))}%` }}
                                  />
                                </div>
                              </div>

                              <div className="grid grid-cols-2 gap-2 pt-2 border-t border-[var(--ecdat-border-subtle)] text-xs font-mono">
                                <div>
                                  <span className="text-slate-500 block text-[10px] uppercase">Public Key</span>
                                  <span className="text-slate-200 font-semibold">{netResult.certificate?.public_key || "RSA-2048"}</span>
                                </div>
                                <div>
                                  <span className="text-slate-500 block text-[10px] uppercase">Signature Algorithm</span>
                                  <span className="text-slate-200 truncate block">{netResult.certificate?.signature_algorithm || "SHA-256"}</span>
                                </div>
                              </div>

                              <div className="pt-2 border-t border-[var(--ecdat-border-subtle)] text-[11px] font-mono text-slate-400 space-y-1">
                                <p className="truncate"><span className="text-slate-600">Subject:</span> {netResult.certificate?.subject || "N/A"}</p>
                                <p className="truncate"><span className="text-slate-600">Issuer:</span> {netResult.certificate?.issuer || "N/A"}</p>
                              </div>
                            </CardContent>
                          </Card>

                          {/* Derived HNDL Exposure Card */}
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardHeader className={`border-b ${C.border} py-3 flex flex-row items-center justify-between`}>
                              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                                Derived HNDL Quantum Exposure
                              </CardTitle>
                              <Badge className={`${sevBadge(netResult.hndl_risk)} text-xs font-bold`}>
                                {netResult.hndl_risk} RISK
                              </Badge>
                            </CardHeader>
                            <CardContent className="p-4 space-y-3">
                              <p className="text-xs text-slate-300 leading-relaxed">
                                {netResult.hndl_rationale}
                              </p>
                              <div className="p-2.5 rounded bg-[var(--ecdat-surface-raised)] border border-[var(--ecdat-border-subtle)] text-[11px] text-slate-400 font-mono space-y-1">
                                <div className="flex justify-between">
                                  <span>Key Exchange Forward Secrecy:</span>
                                  <span className={netResult.key_exchange?.includes("No Forward") ? "text-red-400" : "text-emerald-400"}>
                                    {netResult.key_exchange?.includes("No Forward") ? "VULNERABLE (Static)" : "PROTECTED (PFS)"}
                                  </span>
                                </div>
                                <div className="flex justify-between">
                                  <span>Grover Quantum Search Margin:</span>
                                  <span className={netResult.secret_bits >= 256 ? "text-emerald-400" : "text-amber-400"}>
                                    {netResult.secret_bits >= 256 ? "256-bit (Full Resistance)" : "128-bit (64-bit Effective)"}
                                  </span>
                                </div>
                              </div>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Recommendations */}
                        {(netResult.recommendations?.length ?? 0) > 0 && (
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardHeader className={`border-b ${C.border} py-3`}>
                              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                                Remediation Recommendations
                              </CardTitle>
                            </CardHeader>
                            <CardContent className="py-3 space-y-2">
                              {netResult.recommendations.map((r: string, i: number) => (
                                <div key={i} className={`flex gap-3 text-xs text-slate-300 ${C.raised} border ${C.border} rounded-md px-3 py-2.5`}>
                                  <span className="font-mono text-cyan-500 shrink-0 mt-px">{String(i + 1).padStart(2, "0")}</span>
                                  <span>{r}</span>
                                </div>
                              ))}
                            </CardContent>
                          </Card>
                        )}
                      </motion.div>
                    )}
                  </div>
                )}

                {/* ══════════════════════════════════════════
                    CODE SCANNER
                    ══════════════════════════════════════════ */}
                {activeTab === "code" && (
                  <div className="grid grid-cols-1 xl:grid-cols-[1fr_1fr] gap-5 items-start">

                    {/* Left: editor */}
                    <div className="space-y-3">
                      <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                        <CardHeader className={`border-b ${C.border} py-3 px-4`}>
                          <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                            <Code className="w-3.5 h-3.5 text-cyan-400" />
                            Python Source
                          </CardTitle>
                        </CardHeader>
                        <textarea
                          value={sourceCode}
                          onChange={(e) => setSourceCode(e.target.value)}
                          spellCheck={false}
                          rows={20}
                          className={`w-full px-4 py-3 font-mono text-xs leading-relaxed ${C.canvas} text-slate-300 border-0 resize-none focus:outline-none focus:ring-0`}
                        />
                      </Card>
                      <Button
                        onClick={runCodeScan}
                        disabled={codeLoading}
                        className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm shadow-none"
                      >
                        {codeLoading ? (
                          <><RefreshCcw className="w-3.5 h-3.5 mr-2 animate-spin" />Scanning AST…</>
                        ) : (
                          <><Code className="w-3.5 h-3.5 mr-2" />Run AST Scan</>
                        )}
                      </Button>
                    </div>

                    {/* Right: results */}
                    <div className="space-y-4">
                      {codeLoading ? (
                        <div className="space-y-2">
                          {[0,1,2].map(i => <Skeleton key={i} className={`h-12 ${C.raised} rounded-lg`} />)}
                        </div>
                      ) : !codeScanned ? (
                        <div className={`flex flex-col items-center justify-center h-48 rounded-xl border border-dashed ${C.border} text-slate-600 gap-2`}>
                          <Code className="w-8 h-8 text-slate-700" />
                          <p className="text-sm">Click Run AST Scan to analyse the code.</p>
                        </div>
                      ) : (
                        <>
                          {/* Findings table */}
                          <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                            <CardHeader className={`border-b ${C.border} py-3 px-4`}>
                              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                                Findings
                                <span className="ml-2 font-mono text-slate-600">({findings.length})</span>
                              </CardTitle>
                            </CardHeader>
                            {findings.length === 0 ? (
                              <div className="flex items-center justify-center gap-2 py-10 text-sm text-emerald-400">
                                <CheckCircle2 className="w-4 h-4" />
                                No cryptographic issues detected.
                              </div>
                            ) : (
                              <div className="overflow-auto max-h-64">
                                <Table>
                                  <TableHeader>
                                    <TableRow className={`border-b ${C.border} hover:bg-transparent`}>
                                      <TableHead className="text-[10px] text-slate-500 uppercase tracking-wider py-2.5 w-12">Line</TableHead>
                                      <TableHead className="text-[10px] text-slate-500 uppercase tracking-wider py-2.5">Primitive</TableHead>
                                      <TableHead className="text-[10px] text-slate-500 uppercase tracking-wider py-2.5">Severity</TableHead>
                                      <TableHead className="text-[10px] text-slate-500 uppercase tracking-wider py-2.5">Category</TableHead>
                                    </TableRow>
                                  </TableHeader>
                                  <TableBody>
                                    <AnimatePresence>
                                      {findings.map((f, i) => (
                                        <motion.tr
                                          key={i}
                                          initial={{ opacity: 0, x: -6 }}
                                          animate={{ opacity: 1, x: 0 }}
                                          transition={{ delay: i * 0.05 }}
                                          onClick={() => setSelFinding(selFinding === f ? null : f)}
                                          className={`border-b ${C.border} cursor-pointer transition-colors hover:${C.raised} ${selFinding === f ? `${C.raised} border-l-2 border-l-cyan-500` : ""}`}
                                        >
                                          <TableCell className="font-mono text-slate-500 text-xs py-2.5 pl-4">{f.line}</TableCell>
                                          <TableCell className="font-mono font-semibold text-slate-200 text-xs py-2.5">{f.primitive}</TableCell>
                                          <TableCell className="py-2.5">
                                            <Badge className={`${sevBadge(f.severity)} text-[10px] font-bold`}>{f.severity}</Badge>
                                          </TableCell>
                                          <TableCell className="text-slate-500 text-[11px] py-2.5">{f.category}</TableCell>
                                        </motion.tr>
                                      ))}
                                    </AnimatePresence>
                                  </TableBody>
                                </Table>
                              </div>
                            )}
                          </Card>

                          {/* Finding detail panel */}
                          <AnimatePresence>
                            {selFinding && (
                              <motion.div
                                key="detail"
                                initial={{ opacity: 0, height: 0, marginTop: 0 }}
                                animate={{ opacity: 1, height: "auto", marginTop: 16 }}
                                exit={{ opacity: 0, height: 0, marginTop: 0 }}
                                style={{ overflow: "hidden" }}
                              >
                                <Card className={`${C.surface} ${C.border}`}>
                                  <CardHeader className={`border-b ${C.border} py-3 px-4`}>
                                    <div className="flex items-center justify-between gap-3">
                                      <CardTitle className="font-mono text-xs text-slate-300">{selFinding.primitive}</CardTitle>
                                      <Badge className={`${sevBadge(selFinding.severity)} text-[10px]`}>{selFinding.severity}</Badge>
                                    </div>
                                  </CardHeader>
                                  <CardContent className="py-3 px-4 space-y-3 text-xs">
                                    <div>
                                      <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Code Snippet</p>
                                      <code className={`block ${C.canvas} text-slate-300 font-mono text-[11px] px-3 py-2 rounded border ${C.border}`}>
                                        {selFinding.code}
                                      </code>
                                    </div>
                                    <div className={`grid grid-cols-1 gap-3 pt-1 border-t ${C.border}`}>
                                      <div>
                                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Issue</p>
                                        <p className="text-slate-300 leading-relaxed">{selFinding.issue}</p>
                                      </div>
                                      <div>
                                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">NIST Recommendation</p>
                                        <p className="text-cyan-400 leading-relaxed">{selFinding.nist_recommendation}</p>
                                      </div>
                                      <div>
                                        <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">Quantum Risk</p>
                                        <p className="text-amber-400 leading-relaxed">{selFinding.quantum_risk}</p>
                                      </div>
                                    </div>
                                  </CardContent>
                                </Card>
                              </motion.div>
                            )}
                          </AnimatePresence>

                          {/* Remediation diff */}
                          {remediation && (
                            <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                              <CardHeader className={`border-b ${C.border} py-3 px-4 ${C.raised}`}>
                                <CardTitle className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest">
                                  Remediation Patch — AES-256-GCM Baseline
                                </CardTitle>
                              </CardHeader>
                              <div className="overflow-x-auto bg-[#0d1117] rounded-b-xl">
                                <pre className="text-[11px] font-mono p-4 leading-relaxed">
                                  {remediation.split("\n").map((line, i) => {
                                    const isAdded   = line.startsWith("+") || /AESGCM|sha256|secure_|hasher/.test(line);
                                    const isRemoved = line.startsWith("-") || /\bMD5\b|\bDES\b|\bRC4\b|\bsha1\b/.test(line);
                                    const isComment = line.trimStart().startsWith("#");
                                    return (
                                      <div key={i} className={
                                        isAdded   ? "text-emerald-400 bg-emerald-500/5 px-2 -mx-2 rounded-sm" :
                                        isRemoved ? "text-red-400 bg-red-500/5 px-2 -mx-2 rounded-sm" :
                                        isComment ? "text-slate-600" :
                                        "text-slate-400"
                                      }>
                                        {line || " "}
                                      </div>
                                    );
                                  })}
                                </pre>
                              </div>
                            </Card>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                )}

                {/* ══════════════════════════════════════════
                    RISK & CBOM
                    ══════════════════════════════════════════ */}
                {activeTab === "risk" && (
                  <div className="space-y-5">

                    <div className="grid grid-cols-1 lg:grid-cols-[1fr_380px] gap-5">

                      {/* Mosca controls */}
                      <Card className={`${C.surface} ${C.border}`}>
                        <CardHeader className={`border-b ${C.border} py-4`}>
                          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-slate-200">
                            <Zap className="w-4 h-4 text-amber-400" />
                            Mosca's Theorem — Quantum Urgency Engine
                          </CardTitle>
                          <CardDescription className="text-slate-500 text-xs">
                            Assesses HNDL quantum exposure. Critical when shelf-life (X) + migration time (Y) exceeds CRQC horizon (Z).
                          </CardDescription>
                        </CardHeader>
                        <CardContent className="py-5 space-y-7">
                          {/* Equation bar */}
                          <div className={`${C.raised} border ${C.border} rounded-lg px-4 py-3 flex items-center gap-3 font-mono text-sm`}>
                            <div className="flex items-center gap-1.5">
                              <span className="text-[10px] text-slate-500 uppercase">X</span>
                              <span className="text-lg font-bold text-cyan-400">{x[0]}</span>
                            </div>
                            <span className="text-slate-600">+</span>
                            <div className="flex items-center gap-1.5">
                              <span className="text-[10px] text-slate-500 uppercase">Y</span>
                              <span className="text-lg font-bold text-amber-400">{y[0]}</span>
                            </div>
                            <span className="text-slate-600">=</span>
                            <span className={`text-lg font-bold ${x[0]+y[0] > z[0] ? "text-red-400" : "text-emerald-400"}`}>
                              {x[0]+y[0]}
                            </span>
                            <span className="text-slate-600 mx-1">{x[0]+y[0] > z[0] ? ">" : "≤"}</span>
                            <div className="flex items-center gap-1.5">
                              <span className="text-[10px] text-slate-500 uppercase">Z</span>
                              <span className="text-lg font-bold text-emerald-400">{z[0]}</span>
                            </div>
                            <div className="ml-auto">
                              <Badge className={`text-[10px] font-bold ${x[0]+y[0] > z[0]
                                ? "bg-red-500/10 text-red-400 border border-red-500/20"
                                : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              }`}>
                                {x[0]+y[0] > z[0] ? "⚠ EXPOSED" : "✓ SECURE"}
                              </Badge>
                            </div>
                          </div>

                          {/* Sliders */}
                          {[
                            { label: "X — Data Shelf Life",  desc: "Required confidentiality duration",       val: x, set: setX, max: 30, color: "text-cyan-400"    },
                            { label: "Y — Migration Time",   desc: "Time to complete PQC migration",          val: y, set: setY, max: 15, color: "text-amber-400"   },
                            { label: "Z — CRQC Horizon",     desc: "Estimated arrival of quantum computer",   val: z, set: setZ, max: 20, color: "text-emerald-400" },
                          ].map(({ label, desc, val, set, max, color }) => (
                            <div key={label} className="space-y-2.5">
                              <div className="flex items-center justify-between">
                                <div>
                                  <p className="text-sm font-medium text-slate-300">{label}</p>
                                  <p className="text-[11px] text-slate-500 mt-0.5">{desc}</p>
                                </div>
                                <span className={`text-2xl font-mono font-bold tabular-nums ${color}`}>
                                  {val[0]}<span className="text-xs font-normal text-slate-500 ml-1">yr</span>
                                </span>
                              </div>
                              <Slider
                                value={val}
                                onValueChange={(v: number | readonly number[]) =>
                                  set(Array.isArray(v) ? [...v] : [v as number])
                                }
                                max={max}
                                step={1}
                              />
                            </div>
                          ))}

                          <Button
                            onClick={runMosca}
                            disabled={moscaLoading}
                            className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium shadow-none"
                          >
                            {moscaLoading
                              ? <><RefreshCcw className="w-3.5 h-3.5 mr-2 animate-spin" />Computing…</>
                              : <><Zap className="w-3.5 h-3.5 mr-2" />Calculate Quantum Deficit</>
                            }
                          </Button>
                        </CardContent>
                      </Card>

                      {/* Result + CBOM */}
                      <div className="space-y-4">
                        {mosca && (
                          <Alert className={`border ${mosca.is_critical
                            ? "bg-red-500/8 border-red-500/20 text-red-300"
                            : "bg-emerald-500/8 border-emerald-500/20 text-emerald-300"
                          }`}>
                            <ShieldAlert className="h-4 w-4" />
                            <AlertTitle className="font-bold text-sm">{mosca.posture_status}</AlertTitle>
                            <AlertDescription className="text-xs leading-relaxed mt-1.5 opacity-90">
                              {mosca.explanation}
                            </AlertDescription>
                          </Alert>
                        )}

                        <Card className={`${C.surface} ${C.border}`}>
                          <CardHeader className={`border-b ${C.border} py-3`}>
                            <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                              <BookOpen className="w-3.5 h-3.5 text-slate-500" />
                              CycloneDX v1.6 CBOM
                            </CardTitle>
                            <CardDescription className="text-slate-500 text-[11px] mt-1">
                              ECMA-424 compliant JSON — includes discovered crypto components, quantum-readiness metadata, and NIST FIPS mapping.
                            </CardDescription>
                          </CardHeader>
                          <CardContent className="py-3">
                            <Button
                              onClick={downloadCbom}
                              variant="outline"
                              className={`w-full text-sm font-medium ${C.canvas} ${C.border} hover:${C.raised} text-slate-200 border`}
                            >
                              <Download className="w-3.5 h-3.5 mr-2" />
                              Download CBOM JSON
                            </Button>
                          </CardContent>
                        </Card>
                      </div>
                    </div>

                    {/* NIST Mapping Table */}
                    {mosca?.nist_mapping && mosca.nist_mapping.length > 0 && (
                      <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                        <CardHeader className={`border-b ${C.border} py-4`}>
                          <CardTitle className="text-sm font-semibold text-slate-200">
                            NIST Post-Quantum Migration Roadmap
                          </CardTitle>
                          <CardDescription className="text-slate-500 text-xs">
                            FIPS 203 (ML-KEM) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA) — Aligned with CNSA 2.0 and Executive Order 14412
                          </CardDescription>
                        </CardHeader>
                        <div className="overflow-x-auto">
                          <Table>
                            <TableHeader>
                              <TableRow className={`border-b ${C.border} hover:bg-transparent`}>
                                {["Category","Legacy Primitive","Quantum Threat","PQC Standard","Security Levels","Urgency"].map(h => (
                                  <TableHead key={h} className="text-[10px] text-slate-500 uppercase tracking-wider whitespace-nowrap py-3">{h}</TableHead>
                                ))}
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {mosca.nist_mapping.map((row, i) => (
                                <TableRow key={i} className={`border-b ${C.border} hover:${C.raised} transition-colors`}>
                                  <TableCell className="text-slate-300 text-xs font-medium py-3 whitespace-nowrap">{row.category}</TableCell>
                                  <TableCell className="font-mono text-slate-400 text-xs py-3 whitespace-nowrap">{row.legacy_primitive}</TableCell>
                                  <TableCell className="text-slate-400 text-xs py-3">{row.quantum_threat}</TableCell>
                                  <TableCell className="font-mono text-cyan-400 text-xs font-semibold py-3 whitespace-nowrap">{row.pqc_standard}</TableCell>
                                  <TableCell className="font-mono text-slate-400 text-[11px] py-3 whitespace-nowrap">{row.security_levels}</TableCell>
                                  <TableCell className="py-3">
                                    <Badge className={`${urgencyBadge(row.urgency)} text-[10px] font-bold`}>{row.urgency}</Badge>
                                  </TableCell>
                                </TableRow>
                              ))}
                            </TableBody>
                          </Table>
                        </div>
                      </Card>
                    )}
                  </div>
                )}

              </motion.div>
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
}
