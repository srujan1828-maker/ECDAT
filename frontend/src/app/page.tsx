"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import dynamic from "next/dynamic";
import {
  fetchOverview, scanNetwork, scanCode,
  evaluateMosca, exportCbom, scanBinary,
  evaluateAgility, simulateMigration, fetchPolyglotSamples,
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
  Zap, BookOpen, ChevronRight, XCircle, Cpu, Binary,
  Compass, ShieldCheck, Layers, Terminal, Calendar,
  FileCode2, Check, ExternalLink, Flame
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
  line: number | string;
  code: string;
  primitive: string;
  category: string;
  severity: string;
  issue: string;
  nist_recommendation: string;
  quantum_risk: string;
  language?: string;
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

// ─── Sub-components ───────────────────────────────────────────────────────────

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
        {sub && <p className="text-[11px] text-slate-500 mt-1">{sub}</p>}
      </CardContent>
    </Card>
  );
}

const Divider = () => <div className={`border-t ${C.border}`} />;

const KNOWN_TARGETS = [
  { domain: "google.com",                note: "Modern TLS 1.3 / AES-256-GCM" },
  { domain: "rc4.badssl.com",            note: "RC4 stream cipher — RFC 7465" },
  { domain: "expired.badssl.com",        note: "Expired X.509 certificate" },
  { domain: "null.badssl.com",           note: "NULL cipher — zero encryption" },
  { domain: "tls-v1-0.badssl.com:1010",  note: "TLS 1.0 — POODLE vulnerable" },
  { domain: "sha1-intermediate.badssl.com", note: "SHA-1 intermediate cert" },
];

const NAV = [
  { id: "overview", label: "Overview",            icon: Activity,    desc: "Topology & Blast Radius" },
  { id: "network",  label: "Network Prober",      icon: Globe,       desc: "TLS & Multi-Factor HNDL" },
  { id: "code",     label: "Polyglot Code Scanner", icon: Code,      desc: "Python · Java · C · Go · JS" },
  { id: "binary",   label: "Binary & Firmware",   icon: Binary,      desc: "Module 10: S-Boxes & Hex" },
  { id: "agility",  label: "Agility & Roadmap",   icon: Compass,     desc: "CAI Index & Gantt Roadmap" },
  { id: "risk",     label: "CBOM & Quantum Risk", icon: ShieldAlert, desc: "Mosca & CycloneDX v1.6" },
];

const LANGUAGES = [
  { id: "python",     label: "Python",     ext: ".py" },
  { id: "java",       label: "Java",       ext: ".java" },
  { id: "c_cpp",      label: "C / C++",    ext: ".c" },
  { id: "golang",     label: "Go",         ext: ".go" },
  { id: "javascript", label: "Node.js",    ext: ".js" }
];

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN DASHBOARD
// ═══════════════════════════════════════════════════════════════════════════════

export default function ECDATDashboard() {
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

  // ── Overview State ──
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

  // ── Network State ──
  const [netTarget,  setNetTarget]  = useState("google.com");
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

  // ── Polyglot Code State ──
  const [selectedLang,  setSelectedLang]  = useState("python");
  const [polyglotSamples, setPolyglotSamples] = useState<Record<string, string>>({});
  const [sourceCode,    setSourceCode]    = useState("");
  const [codeLoading,   setCodeLoading]   = useState(false);
  const [findings,      setFindings]      = useState<Finding[]>([]);
  const [remediation,   setRemediation]   = useState("");
  const [selFinding,    setSelFinding]    = useState<Finding | null>(null);
  const [codeScanned,   setCodeScanned]   = useState(false);

  const runCodeScan = async (codeToScan?: string, lang?: string) => {
    setCodeLoading(true);
    setSelFinding(null);
    const targetCode = codeToScan ?? sourceCode;
    const targetLang = lang ?? selectedLang;
    const r = await scanCode(targetCode, targetLang);
    if (r.data) {
      setFindings(r.data.findings ?? []);
      setRemediation(r.data.remediation ?? "");
      setCodeScanned(true);
      loadOverview();
    }
    setCodeLoading(false);
    setLastScan(new Date().toLocaleTimeString());
  };

  const handleLanguageChange = (newLang: string) => {
    setSelectedLang(newLang);
    if (polyglotSamples[newLang]) {
      setSourceCode(polyglotSamples[newLang]);
      runCodeScan(polyglotSamples[newLang], newLang);
    }
  };

  // ── Binary & Firmware State (Module 10) ──
  const [binaryLoading, setBinaryLoading] = useState(false);
  const [binaryResult,  setBinaryResult]  = useState<any>(null);
  const [binaryFileName, setBinaryFileName] = useState("firmware_telemetry.bin");

  const runBinaryScan = async (rawHex?: string, name?: string) => {
    setBinaryLoading(true);
    const r = await scanBinary(rawHex, name ?? binaryFileName);
    if (r.data) {
      setBinaryResult(r.data);
      loadOverview();
    }
    setBinaryLoading(false);
    setLastScan(new Date().toLocaleTimeString());
  };

  // ── Agility & Roadmap State (Module 7 & Gantt) ──
  const [agilityResult,   setAgilityResult]   = useState<any>(null);
  const [migrationRoadmap, setMigrationRoadmap] = useState<any>(null);
  const [agilityParams, setAgilityParams] = useState({
    hardcoded_primitives_count: 3,
    abstracted_primitives_count: 1,
    has_provider_abstraction: false,
    has_pqc_hybrid_support: false,
    automated_cert_rotation: false,
    uses_config_driven_crypto: true,
  });

  const runAgilityEvaluation = async () => {
    const r = await evaluateAgility(agilityParams);
    if (r.data) setAgilityResult(r.data);
  };

  const runMigrationSimulation = async (sx = x[0], sy = y[0], sz = z[0]) => {
    const r = await simulateMigration({
      x_shelf_life: sx,
      y_migration_time: sy,
      z_crqc_horizon: sz,
      critical_findings_count: findings.filter(f => f.severity === "CRITICAL").length || 3,
      qv_certs_count: overview?.kpis.quantum_vulnerable_certs ?? 2
    });
    if (r.data) setMigrationRoadmap(r.data);
  };

  // ── Mosca & CBOM State ──
  const [x, setX] = useState([10]);
  const [y, setY] = useState([4]);
  const [z, setZ] = useState([8]);
  const [mosca,       setMosca]       = useState<MoscaResult | null>(null);
  const [moscaLoading, setMoscaLoading] = useState(false);
  const [cbomFilter, setCbomFilter] = useState("all");

  const runMosca = async () => {
    setMoscaLoading(true);
    const r = await evaluateMosca(x[0], y[0], z[0]);
    if (r.data) setMosca(r.data);
    runMigrationSimulation(x[0], y[0], z[0]);
    setMoscaLoading(false);
  };

  const downloadCbom = async () => {
    const binDets = binaryResult?.detections ?? [];
    const r = await exportCbom(findings, netResult ? [netResult] : [], binDets, "ECDAT-SIH26164-NTRO");
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
    runAgilityEvaluation();
    runBinaryScan(); // pre-load binary analysis

    fetchPolyglotSamples().then((res) => {
      if (res.data) {
        setPolyglotSamples(res.data);
        if (res.data["python"]) {
          setSourceCode(res.data["python"]);
          runCodeScan(res.data["python"], "python");
        }
      }
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ────────────────────────────────────────────────────────────────────────────
  //  RENDER
  // ────────────────────────────────────────────────────────────────────────────
  return (
    <div className={`flex h-screen overflow-hidden ${C.canvas} text-slate-100 font-sans`}>

      {/* ═════════════════ SIDEBAR ═════════════════ */}
      <aside className={`w-64 shrink-0 flex flex-col ${C.surface} border-r ${C.border}`}>

        {/* Brand */}
        <div className={`p-5 flex items-center gap-3 border-b ${C.border}`}>
          <div className="w-9 h-9 rounded-lg bg-cyan-500/15 border border-cyan-500/25 flex items-center justify-center shrink-0">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div className="min-w-0">
            <p className="text-sm font-bold tracking-tight text-slate-100 leading-none">ECDAT</p>
            <p className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">SIH26164 · NTRO Core</p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-2.5 space-y-1 overflow-y-auto">
          {NAV.map(({ id, label, icon: Icon, desc }) => {
            const active = activeTab === id;
            return (
              <button
                key={id}
                onClick={() => setActiveTab(id)}
                className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-md text-left transition-all group ${
                  active
                    ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm"
                    : `text-slate-400 hover:text-slate-200 hover:${C.raised} border border-transparent`
                }`}
              >
                <Icon className={`w-4 h-4 shrink-0 ${active ? "text-cyan-400" : "text-slate-500 group-hover:text-slate-300"}`} />
                <div className="min-w-0">
                  <p className="text-xs font-semibold leading-none truncate">{label}</p>
                  <p className={`text-[10px] mt-0.5 truncate ${active ? "text-cyan-500/80" : "text-slate-600"}`}>{desc}</p>
                </div>
                {active && <ChevronRight className="w-3.5 h-3.5 ml-auto shrink-0 text-cyan-500/60" />}
              </button>
            );
          })}
        </nav>

        {/* Live metrics strip */}
        <div className={`p-3 border-t ${C.border}`}>
          <div className="flex items-center justify-between px-1 mb-2">
            <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-widest">Live Telemetry</span>
            <span className="text-[10px] font-mono text-cyan-400">NTRO Level 4</span>
          </div>
          <div className={`rounded-md ${C.raised} border ${C.border} divide-y divide-[var(--ecdat-border-subtle)]`}>
            {[
              { label: "Assets Indexed", val: overview?.kpis.total_findings,              cls: "text-slate-300" },
              { label: "Critical Debt",  val: overview?.kpis.critical,                    cls: "text-red-400"   },
              { label: "QV Certs",       val: overview?.kpis.quantum_vulnerable_certs,    cls: "text-amber-400" },
              { label: "CAI Agility",    val: agilityResult ? `${agilityResult.cai_percentage}%` : "34%", cls: "text-emerald-400" },
            ].map(({ label, val, cls }) => (
              <div key={label} className="flex items-center justify-between px-3 py-1.5 text-[11px] font-mono">
                <span className="text-slate-500">{label}</span>
                <span className={`font-semibold ${cls}`}>{ovLoading ? "…" : (val ?? "—")}</span>
              </div>
            ))}
          </div>
          {lastScan && (
            <p className="text-[10px] text-slate-600 font-mono mt-2 flex items-center gap-1.5 px-1">
              <Activity className="w-3 h-3 text-emerald-400 animate-pulse" />
              Engine synced {lastScan}
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

          <div className="flex items-center gap-2.5">
            <Badge className="font-mono text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 gap-1.5 py-0.5">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse inline-block" />
              FULL CAPACITY · NTRO SIH26164
            </Badge>
            <Badge className="font-mono text-[10px] bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 py-0.5">
              CycloneDX v1.6
            </Badge>
          </div>
        </header>

        {/* Scrollable content area */}
        <div className="flex-1 overflow-y-auto">
          <div className="p-6">
            <AnimatePresence mode="wait">
              <motion.div
                key={activeTab}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -6 }}
                transition={{ duration: 0.12, ease: "easeOut" }}
              >

                {/* ══════════════════════════════════════════
                    1. OVERVIEW & KNOWLEDGE GRAPH
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
                          label="Total Assets Indexed" value={overview.kpis.total_findings}
                          icon={Database}              accent="bg-cyan-500/10 text-cyan-400"
                          sub="Network · Code · Binary artifacts"
                        />
                        <KpiCard
                          label="Critical Vulnerabilities" value={overview.kpis.critical}
                          valueClass="text-red-400"         icon={ShieldAlert}
                          accent="bg-red-500/10 text-red-400"
                          sub="Classical broken & zero-quantum"
                        />
                        <KpiCard
                          label="Quantum-Vulnerable Certs" value={overview.kpis.quantum_vulnerable_certs}
                          valueClass="text-amber-400"       icon={Lock}
                          accent="bg-amber-500/10 text-amber-400"
                          sub="RSA / ECDSA Shor exposure"
                        />
                        <KpiCard
                          label="Est. Migration Effort"  value={overview.kpis.est_migration_effort}
                          icon={TrendingUp}             accent="bg-emerald-500/10 text-emerald-400"
                          sub="Derived via Mosca deficit"
                        />
                      </div>
                    )}

                    {/* Knowledge Graph Card */}
                    <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                      <CardHeader className={`border-b ${C.border} py-4`}>
                        <div className="flex items-center justify-between gap-4">
                          <div>
                            <CardTitle className="text-sm font-semibold text-slate-200 flex items-center gap-2">
                              <Network className="w-4 h-4 text-cyan-400" />
                              Cryptographic Knowledge Graph (Graph Topology & Blast Radius)
                            </CardTitle>
                            <CardDescription className="text-slate-500 text-xs mt-0.5">
                              Dynamic directed dependency model (`App → Service → Protocol → Primitive → Cert`). Click any node to calculate blast radius impact.
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
                      <div ref={graphRef} className={`w-full h-[500px] ${C.canvas} relative`}>
                        {overview?.graph ? (
                          <ForceGraph2D
                            graphData={overview.graph}
                            width={graphW}
                            height={500}
                            backgroundColor="transparent"
                            nodeRelSize={6}
                            linkColor={() => "#1e293b"}
                            linkWidth={1.5}
                            linkDirectionalArrowLength={4}
                            linkDirectionalArrowRelPos={1}
                            onNodeClick={(n) => setSelectedNode(n as GraphNode)}
                            nodeCanvasObject={(node: any, ctx, scale) => {
                              if (!isFinite(node.x) || !isFinite(node.y)) return;
                              const r = 7;
                              const color = sevNodeColor(node.severity);
                              // Soft radial glow
                              const grad = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, r * 2.5);
                              grad.addColorStop(0, color + "44");
                              grad.addColorStop(1, color + "00");
                              ctx.beginPath();
                              ctx.arc(node.x, node.y, r * 2.5, 0, Math.PI * 2);
                              ctx.fillStyle = grad;
                              ctx.fill();
                              // Node circle
                              ctx.beginPath();
                              ctx.arc(node.x, node.y, r, 0, Math.PI * 2);
                              ctx.fillStyle = color;
                              ctx.fill();
                              ctx.strokeStyle = "rgba(255,255,255,0.2)";
                              ctx.lineWidth = 1;
                              ctx.stroke();
                              // Label text
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
                                <p className="text-sm text-slate-600">Synthesizing Cryptographic Knowledge Graph…</p>
                              </>
                            ) : (
                              <>
                                <Network className="w-8 h-8 text-slate-700" />
                                <p className="text-sm text-slate-600">No graph data currently available.</p>
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
                            <p className="text-[10px] text-slate-500 uppercase tracking-widest font-medium">Computed Blast Radius (Upstream Impact)</p>
                            {(selectedNode.blast_radius?.length ?? 0) > 0 ? (
                              <div className="space-y-1.5 max-h-48 overflow-y-auto">
                                {selectedNode.blast_radius!.map((s, i) => (
                                  <div key={i} className={`flex items-center gap-2.5 text-xs font-mono text-slate-300 px-3 py-2 rounded-md ${C.raised} border ${C.border}`}>
                                    <div className="w-1.5 h-1.5 rounded-full bg-red-400 shrink-0" />
                                    {s}
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="text-sm text-slate-500 italic">Leaf node — no upstream dependent systems found.</p>
                            )}
                          </div>
                        )}
                      </DialogContent>
                    </Dialog>
                  </div>
                )}

                {/* ══════════════════════════════════════════
                    2. NETWORK PROBER (MULTI-FACTOR HNDL)
                    ══════════════════════════════════════════ */}
                {activeTab === "network" && (
                  <div className="space-y-5">
                    <Card className={`${C.surface} ${C.border}`}>
                      <CardHeader className={`border-b ${C.border} py-4`}>
                        <CardTitle className="text-sm font-semibold flex items-center gap-2 text-slate-200">
                          <Network className="w-4 h-4 text-cyan-400" />
                          Dynamic TLS Endpoint & HNDL Risk Inspector
                        </CardTitle>
                        <CardDescription className="text-slate-500 text-xs">
                          Conducts an active non-intrusive TLS handshake. Discovers protocol version, cipher suite, key exchange (KEX), X.509 certificate, and derives true Harvest Now, Decrypt Later (HNDL) exposure.
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
                                  placeholder="Search or type domain..."
                                  className={`text-sm text-slate-200 border-b ${C.border}`}
                                  onValueChange={(v) => { if (v.length > 3 && v.includes(".")) setNetTarget(v); }}
                                />
                                <CommandList>
                                  <CommandEmpty className="text-slate-500 text-sm p-4">Type any valid hostname...</CommandEmpty>
                                  <CommandGroup heading="Curated Audit Endpoints">
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
                            className="bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm shadow-none"
                          >
                            {netLoading ? (
                              <><RefreshCcw className="w-3.5 h-3.5 mr-2 animate-spin" />Probing TLS Socket…</>
                            ) : (
                              <><Activity className="w-3.5 h-3.5 mr-2" />Probe Endpoint</>
                            )}
                          </Button>
                        </div>

                        {/* Error Alert */}
                        {(netResult?.error || netResult?.status === "error") && (
                          <Alert className="mt-4 bg-red-500/10 border-red-500/20 text-red-400">
                            <AlertTriangle className="h-3.5 w-3.5" />
                            <AlertTitle className="text-xs font-semibold">Probe Failed</AlertTitle>
                            <AlertDescription className="font-mono text-[11px] mt-1">
                              {netResult.error ?? netResult.message ?? "Connection refused."}
                            </AlertDescription>
                          </Alert>
                        )}
                      </CardContent>
                    </Card>

                    {/* Results Grid */}
                    {netResult && !netResult.error && netResult.status !== "error" && (
                      <div className="space-y-4">
                        {/* 4 Dimension Cards */}
                        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2">
                              <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold block">Protocol</span>
                              <p className="text-xl font-bold font-mono text-slate-100">{netResult.protocol}</p>
                              <p className="text-[11px] text-slate-500 font-mono truncate">{netResult.target} ({netResult.ip_address})</p>
                            </CardContent>
                          </Card>

                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2">
                              <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold block">Bulk Cipher</span>
                              <p className="text-base font-bold font-mono text-slate-100 truncate">{netResult.bulk_cipher || netResult.cipher_name}</p>
                              <p className="text-[11px] text-cyan-400 font-mono truncate">{netResult.symmetric_security || `${netResult.secret_bits} bits`}</p>
                            </CardContent>
                          </Card>

                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2">
                              <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold block">Key Exchange (KEX)</span>
                              <p className="text-xs font-bold font-mono text-slate-100 leading-snug break-words">{netResult.key_exchange}</p>
                              <p className="text-[11px]">
                                {netResult.key_exchange?.includes("No Forward") ? (
                                  <span className="text-red-400 font-semibold">No Forward Secrecy</span>
                                ) : (
                                  <span className="text-emerald-400">PFS Active</span>
                                )}
                              </p>
                            </CardContent>
                          </Card>

                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2">
                              <span className="text-[10px] uppercase tracking-widest text-slate-500 font-semibold block">PQC / Hybrid Status</span>
                              <p className="text-xs font-bold font-mono text-slate-100 leading-snug">{netResult.pqc_status}</p>
                              <p className="text-[11px]">
                                {netResult.pqc_status?.includes("PQC-Hybrid") ? (
                                  <span className="text-emerald-400">Quantum Resistant</span>
                                ) : netResult.pqc_status?.includes("Zero") ? (
                                  <span className="text-red-400">Zero Quantum Margin</span>
                                ) : (
                                  <span className="text-amber-400">PQC Migration Pending</span>
                                )}
                              </p>
                            </CardContent>
                          </Card>
                        </div>

                        {/* Certificate & Derived HNDL Exposure Row */}
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardHeader className={`border-b ${C.border} py-3`}>
                              <div className="flex items-center justify-between">
                                <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                                  {netResult.certificate?.expired ? <XCircle className="w-3.5 h-3.5 text-red-400" /> : <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />}
                                  X.509 Certificate Parameters
                                </CardTitle>
                                <span className="font-mono text-xs text-slate-300">
                                  {Math.max(0, netResult.certificate?.days_remaining ?? 0)} days remaining
                                </span>
                              </div>
                            </CardHeader>
                            <CardContent className="p-4 space-y-3">
                              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
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

                          <Card className={`${C.surface} ${C.border}`}>
                            <CardHeader className={`border-b ${C.border} py-3 flex flex-row items-center justify-between`}>
                              <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                                <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
                                Derived HNDL Exposure Engine
                              </CardTitle>
                              <Badge className={`${sevBadge(netResult.hndl_risk)} text-xs font-bold`}>
                                {netResult.hndl_risk} RISK
                              </Badge>
                            </CardHeader>
                            <CardContent className="p-4 space-y-2">
                              <p className="text-xs text-slate-300 leading-relaxed">{netResult.hndl_rationale}</p>
                            </CardContent>
                          </Card>
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* ══════════════════════════════════════════
                    3. POLYGLOT CODE SCANNER
                    ══════════════════════════════════════════ */}
                {activeTab === "code" && (
                  <div className="space-y-4">
                    {/* Language Selector Bar */}
                    <div className="flex items-center justify-between bg-[var(--ecdat-surface)] border border-[var(--ecdat-border-subtle)] p-2 rounded-lg">
                      <div className="flex items-center gap-2">
                        <FileCode2 className="w-4 h-4 text-cyan-400 ml-2" />
                        <span className="text-xs font-semibold text-slate-400 uppercase tracking-widest">Target Language:</span>
                        <div className="flex gap-1.5 ml-2">
                          {LANGUAGES.map((l) => (
                            <button
                              key={l.id}
                              onClick={() => handleLanguageChange(l.id)}
                              className={`px-3 py-1 text-xs font-mono rounded transition-colors ${
                                selectedLang === l.id
                                  ? "bg-cyan-500/20 text-cyan-400 border border-cyan-500/30 font-bold"
                                  : "text-slate-400 hover:text-slate-200 hover:bg-[var(--ecdat-surface-raised)]"
                              }`}
                            >
                              {l.label}
                            </button>
                          ))}
                        </div>
                      </div>
                      <Badge className="font-mono text-[10px] bg-slate-800 text-slate-300">
                        {findings.length} findings detected
                      </Badge>
                    </div>

                    <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 items-start">
                      {/* Source Editor */}
                      <div className="space-y-3">
                        <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                          <CardHeader className={`border-b ${C.border} py-3 px-4 flex flex-row items-center justify-between`}>
                            <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                              Source Code Editor
                            </CardTitle>
                            <span className="text-[10px] font-mono text-slate-500">AST Sink Inspection</span>
                          </CardHeader>
                          <textarea
                            value={sourceCode}
                            onChange={(e) => setSourceCode(e.target.value)}
                            spellCheck={false}
                            rows={21}
                            className={`w-full px-4 py-3 font-mono text-xs leading-relaxed ${C.canvas} text-slate-300 border-0 resize-none focus:outline-none focus:ring-0`}
                          />
                        </Card>
                        <Button
                          onClick={() => runCodeScan()}
                          disabled={codeLoading}
                          className="w-full bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-sm shadow-none"
                        >
                          {codeLoading ? <><RefreshCcw className="w-3.5 h-3.5 mr-2 animate-spin" />Analyzing AST Graph…</> : <><Code className="w-3.5 h-3.5 mr-2" />Run Polyglot AST Scan</>}
                        </Button>
                      </div>

                      {/* Findings Table & Drop-in Remediation */}
                      <div className="space-y-4">
                        <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                          <CardHeader className={`border-b ${C.border} py-3 px-4`}>
                            <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                              Discovered Vulnerabilities ({findings.length})
                            </CardTitle>
                          </CardHeader>
                          <div className="overflow-auto max-h-60">
                            <Table>
                              <TableHeader>
                                <TableRow className={`border-b ${C.border}`}>
                                  <TableHead className="text-[10px] text-slate-500 uppercase py-2 w-12">Line</TableHead>
                                  <TableHead className="text-[10px] text-slate-500 uppercase py-2">Primitive</TableHead>
                                  <TableHead className="text-[10px] text-slate-500 uppercase py-2">Severity</TableHead>
                                  <TableHead className="text-[10px] text-slate-500 uppercase py-2">Category</TableHead>
                                </TableRow>
                              </TableHeader>
                              <TableBody>
                                {findings.map((f, i) => (
                                  <TableRow
                                    key={i}
                                    onClick={() => setSelFinding(f === selFinding ? null : f)}
                                    className={`border-b ${C.border} cursor-pointer hover:${C.raised} ${selFinding === f ? `${C.raised} border-l-2 border-l-cyan-500` : ""}`}
                                  >
                                    <TableCell className="font-mono text-slate-500 text-xs py-2">{f.line}</TableCell>
                                    <TableCell className="font-mono font-semibold text-slate-200 text-xs py-2">{f.primitive}</TableCell>
                                    <TableCell className="py-2"><Badge className={`${sevBadge(f.severity)} text-[10px]`}>{f.severity}</Badge></TableCell>
                                    <TableCell className="text-slate-500 text-[11px] py-2">{f.category}</TableCell>
                                  </TableRow>
                                ))}
                              </TableBody>
                            </Table>
                          </div>
                        </Card>

                        {/* Selected Finding Details */}
                        {selFinding && (
                          <Card className={`${C.surface} ${C.border}`}>
                            <CardContent className="p-4 space-y-2 text-xs font-mono">
                              <p className="text-slate-400"><span className="text-cyan-400 font-bold">{selFinding.primitive}:</span> {selFinding.issue}</p>
                              <p className="text-emerald-400"><span className="text-slate-500">Remediation:</span> {selFinding.nist_recommendation}</p>
                            </CardContent>
                          </Card>
                        )}

                        {/* Remediation Patch Block */}
                        {remediation && (
                          <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                            <CardHeader className={`border-b ${C.border} py-2.5 px-4 ${C.raised}`}>
                              <CardTitle className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest">
                                Drop-In Remediation Recipe ({selectedLang.toUpperCase()})
                              </CardTitle>
                            </CardHeader>
                            <div className="overflow-x-auto bg-[#0d1117] p-3 max-h-72">
                              <pre className="text-[11px] font-mono leading-relaxed text-slate-300">
                                {remediation}
                              </pre>
                            </div>
                          </Card>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* ══════════════════════════════════════════
                    4. BINARY & FIRMWARE SCANNER (MODULE 10)
                    ══════════════════════════════════════════ */}
                {activeTab === "binary" && (
                  <div className="space-y-5">
                    <Card className={`${C.surface} ${C.border}`}>
                      <CardHeader className={`border-b ${C.border} py-4`}>
                        <div className="flex items-center justify-between">
                          <div>
                            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-slate-200">
                              <Binary className="w-4 h-4 text-cyan-400" />
                              Module 10: Binary & Firmware Cryptographic Constant / S-Box Scanner
                            </CardTitle>
                            <CardDescription className="text-slate-500 text-xs mt-0.5">
                              Deconstructs compiled ELF/PE binaries, firmware images, and kernel modules. Detects compiled S-boxes (AES, DES), initial state constants (MD5, SHA), and hardcoded private keys.
                            </CardDescription>
                          </div>
                          <Button
                            onClick={() => runBinaryScan()}
                            disabled={binaryLoading}
                            className="bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-none"
                          >
                            {binaryLoading ? <RefreshCcw className="w-3.5 h-3.5 mr-2 animate-spin" /> : <Cpu className="w-3.5 h-3.5 mr-2" />}
                            Triage Synthetic Firmware (.elf)
                          </Button>
                        </div>
                      </CardHeader>
                      <CardContent className="py-4">
                        {binaryResult && (
                          <div className="space-y-5">
                            {/* Entropy & Metric Bar */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                              <Card className={`${C.raised} border ${C.border}`}>
                                <CardContent className="p-3">
                                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">Shannon Entropy</span>
                                  <p className="text-xl font-bold font-mono text-cyan-400 mt-1">{binaryResult.overall_entropy} <span className="text-xs text-slate-500">/ 8.0</span></p>
                                  <p className="text-[10px] text-slate-500 mt-0.5">{binaryResult.entropy_category}</p>
                                </CardContent>
                              </Card>
                              <Card className={`${C.raised} border ${C.border}`}>
                                <CardContent className="p-3">
                                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">Compiled S-Boxes</span>
                                  <p className="text-xl font-bold font-mono text-amber-400 mt-1">{binaryResult.total_detections}</p>
                                  <p className="text-[10px] text-slate-500 mt-0.5">Lookup tables in .rodata</p>
                                </CardContent>
                              </Card>
                              <Card className={`${C.raised} border ${C.border}`}>
                                <CardContent className="p-3">
                                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">Critical Primitives</span>
                                  <p className="text-xl font-bold font-mono text-red-400 mt-1">{binaryResult.critical_count}</p>
                                  <p className="text-[10px] text-slate-500 mt-0.5">DES tables / Static keys</p>
                                </CardContent>
                              </Card>
                              <Card className={`${C.raised} border ${C.border}`}>
                                <CardContent className="p-3">
                                  <span className="text-[10px] uppercase text-slate-500 font-semibold block">Binary Image Size</span>
                                  <p className="text-xl font-bold font-mono text-slate-200 mt-1">{binaryResult.file_size_bytes} <span className="text-xs text-slate-500">bytes</span></p>
                                  <p className="text-[10px] text-slate-500 mt-0.5">{binaryResult.file_name}</p>
                                </CardContent>
                              </Card>
                            </div>

                            {/* Detected S-Boxes Table */}
                            <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                              <CardHeader className={`border-b ${C.border} py-3`}>
                                <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                                  Cryptographic Constants Located in Memory
                                </CardTitle>
                              </CardHeader>
                              <div className="overflow-auto">
                                <Table>
                                  <TableHeader>
                                    <TableRow className={`border-b ${C.border}`}>
                                      <TableHead className="text-[10px] text-slate-500 uppercase py-2">Offset</TableHead>
                                      <TableHead className="text-[10px] text-slate-500 uppercase py-2">Primitive</TableHead>
                                      <TableHead className="text-[10px] text-slate-500 uppercase py-2">Type</TableHead>
                                      <TableHead className="text-[10px] text-slate-500 uppercase py-2">Severity</TableHead>
                                      <TableHead className="text-[10px] text-slate-500 uppercase py-2">Quantum Impact</TableHead>
                                    </TableRow>
                                  </TableHeader>
                                  <TableBody>
                                    {binaryResult.detections?.map((d: any, idx: number) => (
                                      <TableRow key={idx} className={`border-b ${C.border} font-mono text-xs`}>
                                        <TableCell className="text-cyan-400 font-bold">{d.offset}</TableCell>
                                        <TableCell className="text-slate-200">{d.primitive}</TableCell>
                                        <TableCell className="text-slate-400 text-[11px]">{d.type}</TableCell>
                                        <TableCell><Badge className={`${sevBadge(d.severity)} text-[10px]`}>{d.severity}</Badge></TableCell>
                                        <TableCell className="text-slate-400 text-[11px]">{d.quantum_impact}</TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </div>
                            </Card>

                            {/* Hex & Byte Preview */}
                            <Card className={`${C.surface} ${C.border}`}>
                              <CardHeader className={`border-b ${C.border} py-2.5 px-4 ${C.raised}`}>
                                <CardTitle className="text-[10px] font-semibold text-slate-400 uppercase tracking-widest">
                                  Raw Image Hex Dump (First 256 Bytes)
                                </CardTitle>
                              </CardHeader>
                              <div className="p-4 bg-[#0a0e17] overflow-x-auto">
                                <code className="text-[10px] font-mono text-cyan-500/90 leading-relaxed block break-all">
                                  {binaryResult.hex_preview}
                                </code>
                              </div>
                            </Card>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </div>
                )}

                {/* ══════════════════════════════════════════
                    5. CRYPTO-AGILITY & MIGRATION ROADMAP
                    ══════════════════════════════════════════ */}
                {activeTab === "agility" && (
                  <div className="space-y-5">
                    {/* Top row: CAI Score & Posture */}
                    {agilityResult && (
                      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
                        <Card className={`${C.surface} ${C.border} lg:col-span-1`}>
                          <CardHeader className="pb-2">
                            <span className="text-[10px] uppercase text-slate-500 font-semibold tracking-widest">Cryptographic Agility Index (CAI)</span>
                            <CardTitle className="text-4xl font-bold font-mono text-cyan-400 mt-2">
                              {agilityResult.cai_score} <span className="text-sm font-normal text-slate-500">/ 1.00</span>
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <Badge className={`${agilityResult.cai_score >= 0.8 ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-red-500/10 text-red-400 border-red-500/20"} font-bold text-xs`}>
                              {agilityResult.tier}
                            </Badge>
                            <p className="text-xs text-slate-300 leading-relaxed">{agilityResult.posture}</p>
                            <Divider />
                            <div className="flex justify-between text-xs font-mono text-slate-400">
                              <span>Estimated Migration Span:</span>
                              <span className="text-slate-200 font-bold">{agilityResult.migration_readiness_weeks} Weeks</span>
                            </div>
                          </CardContent>
                        </Card>

                        {/* 4 Pillars Breakdown */}
                        <Card className={`${C.surface} ${C.border} lg:col-span-2`}>
                          <CardHeader className={`border-b ${C.border} py-3`}>
                            <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                              Four Architectural Pillars of Crypto-Agility
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="p-4 space-y-4">
                            {agilityResult.pillars?.map((p: any, idx: number) => (
                              <div key={idx} className="space-y-1.5">
                                <div className="flex justify-between text-xs">
                                  <span className="font-semibold text-slate-200">{p.name}</span>
                                  <span className="font-mono text-cyan-400 font-bold">{p.score}%</span>
                                </div>
                                <div className={`w-full h-1.5 rounded-full ${C.raised} overflow-hidden`}>
                                  <div
                                    className={`h-full rounded-full ${p.score >= 70 ? "bg-emerald-500" : (p.score >= 40 ? "bg-amber-500" : "bg-red-500")}`}
                                    style={{ width: `${p.score}%` }}
                                  />
                                </div>
                                <p className="text-[11px] text-slate-500 font-mono">{p.recommendation}</p>
                              </div>
                            ))}
                          </CardContent>
                        </Card>
                      </div>
                    )}

                    {/* Executive Migration Roadmap (Gantt-Style) */}
                    {migrationRoadmap && (
                      <Card className={`${C.surface} ${C.border}`}>
                        <CardHeader className={`border-b ${C.border} py-4`}>
                          <div className="flex items-center justify-between">
                            <div>
                              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-slate-200">
                                <Calendar className="w-4 h-4 text-cyan-400" />
                                Executive PQC Migration Roadmap & Implementation Schedule
                              </CardTitle>
                              <CardDescription className="text-slate-500 text-xs mt-0.5">
                                Phased schedule targeting compliance with NSA CNSA 2.0, NIST FIPS 203/204/205, and India's National Quantum Mission (NQM).
                              </CardDescription>
                            </div>
                            <div className="flex gap-2">
                              <Badge className="font-mono text-xs bg-slate-800 text-slate-300">
                                Effort: {migrationRoadmap.person_months} Person-Months
                              </Badge>
                              <Badge className="font-mono text-xs bg-cyan-950 text-cyan-400 border border-cyan-800">
                                Est. Budget: {migrationRoadmap.estimated_budget}
                              </Badge>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="p-5 space-y-5">
                          {migrationRoadmap.phases?.map((ph: any, idx: number) => (
                            <div key={idx} className={`p-4 rounded-lg ${C.raised} border ${C.border} space-y-3`}>
                              <div className="flex items-center justify-between">
                                <span className="font-bold text-sm text-slate-200">{ph.phase}</span>
                                <div className="flex items-center gap-2">
                                  <span className="text-xs font-mono text-cyan-400">{ph.timeline}</span>
                                  <Badge className={`${urgencyBadge(ph.priority)} text-[10px]`}>{ph.priority}</Badge>
                                </div>
                              </div>
                              <p className="text-xs text-slate-400"><span className="text-slate-500 uppercase font-semibold">Scope:</span> {ph.scope}</p>
                              <ul className="space-y-1">
                                {ph.action_items.map((act: string, aIdx: number) => (
                                  <li key={aIdx} className="text-xs text-slate-300 flex items-start gap-2">
                                    <Check className="w-3.5 h-3.5 text-emerald-400 mt-0.5 shrink-0" />
                                    <span>{act}</span>
                                  </li>
                                ))}
                              </ul>
                              <p className="text-xs text-emerald-400 font-mono pt-1"><span className="text-slate-500">Milestone:</span> {ph.milestone}</p>
                            </div>
                          ))}
                        </CardContent>
                      </Card>
                    )}
                  </div>
                )}

                {/* ══════════════════════════════════════════
                    6. CBOM & QUANTUM RISK (MOSCA & CYCLONEDX)
                    ══════════════════════════════════════════ */}
                {activeTab === "risk" && (
                  <div className="space-y-5">
                    {/* Mosca Sliders Row */}
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                      <Card className={`${C.surface} ${C.border}`}>
                        <CardHeader className={`border-b ${C.border} py-3`}>
                          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-slate-200">
                            <Zap className="w-4 h-4 text-amber-400" />
                            Mosca's Theorem Urgency Calculator (X + Y &gt; Z)
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="p-4 space-y-5">
                          {/* Live Equation Bar */}
                          <div className={`${C.raised} border ${C.border} rounded-lg px-4 py-2.5 flex items-center gap-3 font-mono text-sm`}>
                            <span className="text-cyan-400 font-bold">X: {x[0]}yr</span>
                            <span className="text-slate-600">+</span>
                            <span className="text-amber-400 font-bold">Y: {y[0]}yr</span>
                            <span className="text-slate-600">=</span>
                            <span className={`font-bold ${x[0]+y[0] > z[0] ? "text-red-400" : "text-emerald-400"}`}>{x[0]+y[0]}yr</span>
                            <span className="text-slate-600 mx-1">{x[0]+y[0] > z[0] ? ">" : "≤"}</span>
                            <span className="text-emerald-400 font-bold">Z: {z[0]}yr</span>
                            <Badge className={`ml-auto text-[10px] ${x[0]+y[0] > z[0] ? "bg-red-500/10 text-red-400 border border-red-500/20" : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"}`}>
                              {x[0]+y[0] > z[0] ? "EXPOSED" : "SECURE"}
                            </Badge>
                          </div>

                          {[
                            { label: "X — Data Shelf Life",  desc: "Required confidentiality span",   val: x, set: setX, max: 30, color: "text-cyan-400"    },
                            { label: "Y — Migration Time",   desc: "Duration to complete transition", val: y, set: setY, max: 15, color: "text-amber-400"   },
                            { label: "Z — CRQC Horizon",     desc: "Estimated quantum arrival",       val: z, set: setZ, max: 20, color: "text-emerald-400" },
                          ].map(({ label, desc, val, set, max, color }) => (
                            <div key={label} className="space-y-1.5">
                              <div className="flex items-center justify-between">
                                <span className="text-xs font-medium text-slate-300">{label}</span>
                                <span className={`text-base font-mono font-bold ${color}`}>{val[0]} yr</span>
                              </div>
                              <Slider value={val} onValueChange={(v) => set(Array.isArray(v) ? [...v] : [v as number])} max={max} step={1} />
                            </div>
                          ))}
                          <Button onClick={runMosca} className="w-full bg-cyan-600 hover:bg-cyan-500 text-white text-xs">
                            Recalculate Mosca Deficit
                          </Button>
                        </CardContent>
                      </Card>

                      {/* Posture Alert & CBOM Export */}
                      <div className="space-y-4">
                        {mosca && (
                          <Alert className={`border ${mosca.is_critical ? "bg-red-500/10 border-red-500/20 text-red-300" : "bg-emerald-500/10 border-emerald-500/20 text-emerald-300"}`}>
                            <ShieldAlert className="h-4 w-4" />
                            <AlertTitle className="font-bold text-sm">{mosca.posture_status}</AlertTitle>
                            <AlertDescription className="text-xs mt-1 leading-relaxed opacity-90">{mosca.explanation}</AlertDescription>
                          </Alert>
                        )}

                        <Card className={`${C.surface} ${C.border}`}>
                          <CardHeader className="py-3">
                            <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest flex items-center gap-2">
                              <BookOpen className="w-3.5 h-3.5 text-cyan-400" />
                              CycloneDX v1.6 (ECMA-424) CBOM Generator
                            </CardTitle>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <p className="text-xs text-slate-400 leading-relaxed">
                              Exports standard Cryptographic Bill of Materials (CBOM) capturing discovered network ciphers, code primitives, and compiled binary S-boxes.
                            </p>
                            <Button onClick={downloadCbom} variant="outline" className={`w-full text-xs ${C.canvas} ${C.border} text-slate-200`}>
                              <Download className="w-3.5 h-3.5 mr-2" /> Download CycloneDX v1.6 CBOM JSON
                            </Button>
                          </CardContent>
                        </Card>
                      </div>
                    </div>

                    {/* NIST PQC Standards Mapping Table */}
                    {mosca?.nist_mapping && (
                      <Card className={`${C.surface} ${C.border} overflow-hidden`}>
                        <CardHeader className={`border-b ${C.border} py-3`}>
                          <CardTitle className="text-xs font-semibold text-slate-400 uppercase tracking-widest">
                            NIST Post-Quantum Cryptography (PQC) Transition Standards
                          </CardTitle>
                        </CardHeader>
                        <div className="overflow-x-auto">
                          <Table>
                            <TableHeader>
                              <TableRow className={`border-b ${C.border}`}>
                                {["Category","Legacy Primitive","Threat","PQC Standard (NIST)","Security Levels","Urgency"].map(h => (
                                  <TableHead key={h} className="text-[10px] text-slate-500 uppercase py-2.5 whitespace-nowrap">{h}</TableHead>
                                ))}
                              </TableRow>
                            </TableHeader>
                            <TableBody>
                              {mosca.nist_mapping.map((row, i) => (
                                <TableRow key={i} className={`border-b ${C.border} text-xs`}>
                                  <TableCell className="text-slate-300 font-medium whitespace-nowrap">{row.category}</TableCell>
                                  <TableCell className="font-mono text-slate-400 whitespace-nowrap">{row.legacy_primitive}</TableCell>
                                  <TableCell className="text-slate-400">{row.quantum_threat}</TableCell>
                                  <TableCell className="font-mono text-cyan-400 font-semibold whitespace-nowrap">{row.pqc_standard}</TableCell>
                                  <TableCell className="font-mono text-slate-400 text-[11px] whitespace-nowrap">{row.security_levels}</TableCell>
                                  <TableCell><Badge className={`${urgencyBadge(row.urgency)} text-[10px]`}>{row.urgency}</Badge></TableCell>
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
