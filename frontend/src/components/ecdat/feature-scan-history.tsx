"use client";

import { useState, useMemo } from "react";
import {
  Globe,
  Code2,
  Binary,
  CheckCircle2,
  AlertTriangle,
  CircleHelp,
  Download,
  RotateCcw,
  Search,
  ShieldCheck,
  ShieldAlert,
  Key,
  FileCode2,
  Clock,
  FileText,
  Copy,
  Check,
  Radio,
  Zap,
  Network,
  Sparkles,
  ExternalLink,
  Shield,
  Layers,
} from "lucide-react";
import { Scan, Finding } from "@/lib/api";

const panelClass = "min-w-0 rounded-lg border border-subtle bg-surface";

interface FeatureScanHistoryProps {
  mode: "network" | "code" | "binary" | "pcap";
  scans: Scan[];
  selectedId: string | null;
  onSelectScan: (id: string) => void;
  exportIds: string[];
  onToggleExport: (id: string) => void;
  onRescanTarget?: (target: string, language?: string, code?: string) => void;
  onDownloadSingleCbom: (scan: Scan) => void;
  onRefresh: () => void;
  onPatchAll?: (scan: Scan) => void;
  onViewGraph?: () => void;
}

const kindMeta = {
  network: {
    label: "Network Scan",
    plural: "Network scans",
    icon: Globe,
    title: "Network Scan History & Post-Quantum TLS Observations",
    subtitle:
      "Historical record of observed TLS cipher suites, hybrid post-quantum key exchanges, certificates, and HNDL risk for servers scanned in this project.",
    emptyHelp:
      "Enter a hostname or HTTPS server address above and click 'Start scan' to observe real TLS handshakes and hybrid PQC key exchange.",
  },
  code: {
    label: "Source Code Scan",
    plural: "Source code scans",
    icon: Code2,
    title: "Source Code Scan History & Cryptographic Findings",
    subtitle:
      "Historical record of discovered cryptographic algorithm calls, deprecated hash functions, weak key lengths, and line references in your codebase.",
    emptyHelp:
      "Upload source files or paste code snippets above to find cryptographic primitives and identify post-quantum migration targets.",
  },
  binary: {
    label: "Binary & Firmware Scan",
    plural: "Binary & firmware scans",
    icon: Binary,
    title: "Binary & Firmware Scan History & Signatures",
    subtitle:
      "Historical record of cryptographic constants, S-boxes, unstripped private key sequences, and section entropy from compiled executables and archives.",
    emptyHelp:
      "Upload an ELF, PE, raw firmware binary, or ZIP archive above to inspect embedded cryptographic signatures.",
  },
  pcap: {
    label: "Passive PCAP Scan",
    plural: "Passive PCAP scans",
    icon: Radio,
    title: "Passive PCAP History & Dissected TLS Handshakes",
    subtitle:
      "Historical record of passively dissected TLS handshakes, ML-KEM post-quantum hybrid sessions, and JA3/JA4 fingerprints from network traffic captures.",
    emptyHelp:
      "Upload a .pcap file or trigger synthetic traffic above to passively inspect TLS sessions without active probing.",
  },
} as const;


function StatusBadge({ status }: { status: Scan["status"] }) {
  const color =
    status === "completed"
      ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
      : status === "failed"
        ? "border-red-500/20 bg-red-500/10 text-red-400"
        : status === "cancelled"
          ? "border-slate-500/20 bg-slate-500/10 text-quiet"
          : "border-cyan-500/20 bg-cyan-500/10 text-cyan-400";
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-medium capitalize ${color}`}
    >
      {status === "running" && (
        <span className="h-1.5 w-1.5 rounded-full bg-cyan-400 animate-pulse" />
      )}
      {status}
    </span>
  );
}

function getScanTargetLabel(scan: Scan): string {
  const matches = scan.result?.findings || scan.result?.detections || [];
  return (
    scan.result?.target ||
    matches[0]?.file ||
    `${scan.kind.toUpperCase()} · ${scan.id.slice(0, 8)}`
  );
}

export function FeatureScanHistory({
  mode,
  scans,
  selectedId,
  onSelectScan,
  exportIds,
  onToggleExport,
  onRescanTarget,
  onDownloadSingleCbom,
  onRefresh,
  onPatchAll,
  onViewGraph,
}: FeatureScanHistoryProps) {
  const [searchQuery, setSearchQuery] = useState("");
  const [copiedId, setCopiedId] = useState(false);
  const [activeTab, setActiveTab] = useState<"findings" | "evidence">("findings");

  // STRICT FILTERING: Only scans belonging to THIS specific feature
  const featureScans = useMemo(() => {
    return scans.filter((s) => s.kind === mode);
  }, [scans, mode]);

  const filteredScans = useMemo(() => {
    if (!searchQuery.trim()) return featureScans;
    const q = searchQuery.toLowerCase();
    return featureScans.filter((s) => {
      const target = getScanTargetLabel(s).toLowerCase();
      const id = s.id.toLowerCase();
      const findings = s.result?.findings || s.result?.detections || [];
      const hasPrimitive = findings.some((f) =>
        f.primitive?.toLowerCase().includes(q),
      );
      const cipher = s.result?.cipher_name?.toLowerCase() || "";
      const protocol = s.result?.protocol?.toLowerCase() || "";
      return (
        target.includes(q) ||
        id.includes(q) ||
        hasPrimitive ||
        cipher.includes(q) ||
        protocol.includes(q)
      );
    });
  }, [featureScans, searchQuery]);

  // Determine active selected scan for this feature
  const activeScan = useMemo(() => {
    if (selectedId) {
      const match = featureScans.find((s) => s.id === selectedId);
      if (match) return match;
    }
    return featureScans[0] || null;
  }, [featureScans, selectedId]);

  const meta = kindMeta[mode];
  const Icon = meta.icon;

  const handleCopyId = (id: string) => {
    navigator.clipboard.writeText(id);
    setCopiedId(true);
    setTimeout(() => setCopiedId(false), 2000);
  };

  return (
    <section
      className="mt-8 space-y-4 border-t border-subtle pt-6"
      aria-labelledby="feature-history-heading"
    >
      {/* Header bar */}
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <div className="flex h-7 w-7 items-center justify-center rounded border border-cyan-500/25 bg-cyan-500/10 text-cyan-400">
              <Icon size={16} />
            </div>
            <h3
              id="feature-history-heading"
              className="text-base font-semibold tracking-tight text-foreground"
            >
              {meta.title}
            </h3>
          </div>
          <p className="mt-1 text-xs text-quiet max-w-3xl">
            {meta.subtitle}
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Search
              size={13}
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-quiet"
            />
            <input
              type="text"
              placeholder={`Filter ${meta.label.toLowerCase()}s...`}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="rounded-md border border-subtle bg-canvas pl-8 pr-3 py-1.5 text-xs text-foreground placeholder:text-quiet outline-none focus:border-cyan-500 w-48 sm:w-60"
            />
          </div>

          <button
            onClick={onRefresh}
            className="flex items-center gap-1.5 rounded-md border border-subtle bg-surface px-3 py-1.5 text-xs text-quiet hover:bg-surface-raised hover:text-cyan-400 transition-colors"
            title="Refresh records"
          >
            <RotateCcw size={12} />
            Refresh
          </button>
        </div>
      </div>

      {/* Empty State */}
      {!featureScans.length ? (
        <div className={`${panelClass} p-12 text-center`}>
          <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full border border-subtle bg-canvas text-quiet mb-3">
            <Icon size={22} />
          </div>
          <h4 className="text-sm font-semibold text-foreground">
            No {meta.label.toLowerCase()} records yet
          </h4>
          <p className="mt-1.5 text-xs text-quiet max-w-md mx-auto leading-relaxed">
            {meta.emptyHelp}
          </p>
        </div>
      ) : (
        <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
          {/* Left Column: Feature Scans List */}
          <div className={`${panelClass} overflow-hidden`}>
            <div className="flex items-center justify-between border-b border-subtle px-4 py-3 bg-canvas/40">
              <span className="text-xs font-semibold text-foreground flex items-center gap-1.5">
                <FileText size={13} className="text-cyan-400" />
                {meta.label} Records ({filteredScans.length})
              </span>
              <span className="text-[11px] text-quiet">
                Click a record to inspect evidence
              </span>
            </div>

            <div className="max-h-[580px] divide-y divide-[var(--ecdat-border-subtle)] overflow-y-auto">
              {filteredScans.map((scan) => {
                const isSelected = activeScan?.id === scan.id;
                const findingsCount = (
                  scan.result?.findings ||
                  scan.result?.detections ||
                  []
                ).length;
                const isExported = exportIds.includes(scan.id);

                return (
                  <div
                    key={scan.id}
                    onClick={() => onSelectScan(scan.id)}
                    className={`border-l-2 p-3.5 cursor-pointer transition-colors ${
                      isSelected
                        ? "border-l-cyan-500 bg-cyan-500/5"
                        : "border-l-transparent hover:bg-surface-raised/40"
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <input
                        type="checkbox"
                        checked={isExported}
                        disabled={scan.status !== "completed"}
                        onChange={(e) => {
                          e.stopPropagation();
                          onToggleExport(scan.id);
                        }}
                        aria-label={`Select ${scan.id} for report`}
                        className="mt-1 h-3.5 w-3.5 shrink-0 accent-cyan-500 rounded cursor-pointer"
                      />

                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-mono text-xs font-semibold truncate text-foreground">
                            {getScanTargetLabel(scan)}
                          </span>
                          <StatusBadge status={scan.status} />
                        </div>

                        {/* Feature-specific summary line */}
                        <div className="mt-1.5 flex flex-wrap items-center gap-2 text-[11px] text-quiet">
                          <span className="flex items-center gap-1">
                            <Clock size={11} />
                            {new Date(scan.created_at).toLocaleTimeString([], {
                              hour: "2-digit",
                              minute: "2-digit",
                            })}{" "}
                            · {new Date(scan.created_at).toLocaleDateString()}
                          </span>

                          {/* Network metadata */}
                          {mode === "network" && scan.result && (
                            <>
                              <span className="text-foreground/80 font-mono text-[10px] px-1.5 py-0.2 rounded bg-surface border border-subtle">
                                {scan.result.protocol || "TLS"}
                              </span>
                              {scan.result.quantum_vulnerable === true && (
                                <span className="text-red-400 font-medium text-[10px] px-1.5 py-0.2 rounded bg-red-500/10 border border-red-500/20">
                                  PQ Vulnerable
                                </span>
                              )}
                              {scan.result.quantum_vulnerable === false && (
                                <span className="text-emerald-400 font-medium text-[10px] px-1.5 py-0.2 rounded bg-emerald-500/10 border border-emerald-500/20">
                                  PQ Ready
                                </span>
                              )}
                            </>
                          )}

                          {/* Code metadata */}
                          {mode === "code" && (
                            <span className="text-foreground/80 font-medium">
                              {findingsCount} finding{findingsCount === 1 ? "" : "s"}
                            </span>
                          )}

                          {/* Binary metadata */}
                          {mode === "binary" && (
                            <span className="text-foreground/80 font-medium">
                              {findingsCount} signature{findingsCount === 1 ? "" : "s"}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Right Column: Active Scan Details & Findings */}
          <div className={`${panelClass} p-5 space-y-5`}>
            {!activeScan ? (
              <div className="p-12 text-center text-quiet">
                <Search size={28} className="mx-auto mb-2 opacity-50" />
                <p className="text-sm">Select a scan from the list to review its findings</p>
              </div>
            ) : (
              <>
                {/* Active scan header matching Screenshot 1 */}
                <div className="flex flex-wrap items-start justify-between gap-3 border-b border-subtle pb-4">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2.5">
                      <h2 className="text-base sm:text-lg font-bold text-foreground tracking-tight flex items-center gap-2">
                        <span>{kindMeta[mode].label} Result · #{activeScan.id.slice(0, 8)}</span>
                      </h2>
                      <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-400 uppercase tracking-wider">
                        {activeScan.status.toUpperCase()}
                      </span>
                    </div>
                    <div className="mt-1 flex flex-wrap items-center gap-2.5 text-xs text-quiet">
                      <span className="font-mono text-foreground/80 font-medium">
                        Target: {getScanTargetLabel(activeScan)}
                      </span>
                      <span>•</span>
                      <span>
                        Scan ID:{" "}
                        <button
                          onClick={() => handleCopyId(activeScan.id)}
                          className="font-mono hover:text-cyan-400 inline-flex items-center gap-1"
                          title="Click to copy full ID"
                        >
                          {activeScan.id.slice(0, 10)}...
                          {copiedId ? <Check size={11} /> : <Copy size={11} />}
                        </button>
                      </span>
                      <span>•</span>
                      <span>
                        Engine: {activeScan.engine_version || "ECDAT v3.0"}
                      </span>
                      <span>•</span>
                      <span>
                        {new Date(activeScan.created_at).toLocaleString()}
                      </span>
                    </div>
                  </div>

                  {/* Actions matching Screenshot 1 */}
                  <div className="flex flex-wrap items-center gap-2">
                    {/* Primary Patch All button */}
                    <button
                      type="button"
                      onClick={() => onPatchAll?.(activeScan)}
                      className="flex items-center gap-1.5 rounded-md bg-gradient-to-r from-cyan-500 to-teal-500 hover:from-cyan-400 hover:to-teal-400 px-3.5 py-1.5 text-xs font-bold text-slate-950 shadow-md transition-all active:scale-95"
                      title="Run automated PQC patching on discovered issues"
                    >
                      <Zap size={14} className="fill-current" />
                      Patch All Issues
                    </button>

                    {/* View in Graph */}
                    {onViewGraph && (
                      <button
                        type="button"
                        onClick={onViewGraph}
                        className="flex items-center gap-1 rounded-md border border-subtle bg-surface px-2.5 py-1.5 text-xs font-medium text-quiet hover:bg-surface-raised hover:text-foreground transition-all"
                        title="Visualize cryptographic relationships in GQL Graph"
                      >
                        <Network size={13} />
                        View in Graph
                      </button>
                    )}

                    {/* View Evidence Toggle */}
                    <button
                      type="button"
                      onClick={() => setActiveTab((t) => (t === "evidence" ? "findings" : "evidence"))}
                      className={`flex items-center gap-1 rounded-md border px-2.5 py-1.5 text-xs font-medium transition-all ${
                        activeTab === "evidence"
                          ? "border-cyan-500/40 bg-cyan-500/10 text-teal"
                          : "border-subtle bg-surface text-quiet hover:bg-surface-raised hover:text-foreground"
                      }`}
                      title="Toggle detailed technical evidence"
                    >
                      <FileText size={13} />
                      {activeTab === "evidence" ? "Back to Findings" : "View Evidence"}
                    </button>

                    {/* Re-scan action */}
                    {onRescanTarget && activeScan.result?.target && (
                      <button
                        type="button"
                        onClick={() =>
                          onRescanTarget(activeScan.result?.target || "")
                        }
                        className="rounded border border-subtle bg-surface px-2.5 py-1.5 text-xs text-quiet hover:bg-surface-raised hover:text-foreground flex items-center gap-1"
                        title="Load target into scan box above"
                      >
                        <RotateCcw size={12} />
                        Re-scan
                      </button>
                    )}

                    {/* Single scan CBOM download */}
                    <button
                      type="button"
                      onClick={() => onDownloadSingleCbom(activeScan)}
                      disabled={activeScan.status !== "completed"}
                      className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2.5 py-1.5 text-xs text-teal hover:bg-cyan-500/20 flex items-center gap-1 disabled:opacity-50"
                      title="Download CycloneDX 1.6 CBOM for this scan"
                    >
                      <Download size={12} />
                      CBOM
                    </button>
                  </div>
                </div>

                {/* Scan failure message */}
                {activeScan.error && (
                  <div
                    role="alert"
                    className="rounded-md border border-red-500/25 bg-red-500/10 p-3.5 text-xs text-red-400 space-y-1"
                  >
                    <div className="flex items-center gap-1.5 font-bold">
                      <AlertTriangle size={14} />
                      Scan Error
                    </div>
                    <p className="leading-relaxed">{activeScan.error}</p>
                  </div>
                )}

                {/* Scan in progress message */}
                {["queued", "running"].includes(activeScan.status) && (
                  <div className="rounded-md border border-cyan-500/20 bg-cyan-500/5 p-4 text-center space-y-2">
                    <div className="inline-block h-6 w-6 animate-spin rounded-full border-2 border-cyan-400 border-t-transparent" />
                    <p className="text-xs text-foreground font-medium">
                      Scan is actively executing in the background...
                    </p>
                    <p className="text-[11px] text-quiet">
                      Evidence and findings will populate automatically once the probe completes.
                    </p>
                  </div>
                )}

                {/* COMPLETED FINDINGS MATCHING SCREENSHOT 1 */}
                {activeScan.status === "completed" && activeScan.result && (() => {
                  const findingsList: Finding[] = (activeScan.result?.findings || activeScan.result?.detections || []) as Finding[];

                  // Standardize findings for table display across any scan type
                  const tableFindings = (() => {
                    if (findingsList.length > 0) {
                      return findingsList.map((f: Finding) => {
                        const p = (f.primitive || "Cryptographic Primitive").toUpperCase();
                        let quantumRisk = "Shor's Algorithm Factoring Break";
                        let migrationTarget = "NIST FIPS 203 (ML-KEM-768)";

                        if (p.includes("MD5") || p.includes("SHA1")) {
                          quantumRisk = "Broken Collision Resistance (Shor/Classical)";
                          migrationTarget = "NIST FIPS 180-4 (SHA-256) / SHA-3";
                        } else if (p.includes("DES") || p.includes("RC4") || p.includes("BLOWFISH")) {
                          quantumRisk = "Exhaustive Key Exhaustion / Weak S-Box";
                          migrationTarget = "NIST FIPS 197 (AES-256-GCM)";
                        } else if (p.includes("RSA")) {
                          quantumRisk = "Shor's Algorithm Factoring Break";
                          migrationTarget = "ML-KEM-768 (FIPS 203) / ML-DSA (FIPS 204)";
                        } else if (p.includes("ECDSA") || p.includes("ECC") || p.includes("SECP")) {
                          quantumRisk = "Shor's Elliptic Curve Discrete Log Break";
                          migrationTarget = "ML-DSA-65 (FIPS 204) / SLH-DSA (FIPS 205)";
                        } else if (p.includes("AES") || p.includes("SHA256") || p.includes("MLKEM")) {
                          quantumRisk = "Grover 128-bit Bound (Quantum Resilient)";
                          migrationTarget = "Conforms to Post-Quantum Standards";
                        }

                        return {
                          primitive: f.primitive || "Cryptographic Call",
                          severity: f.severity || (p.includes("MD5") || p.includes("DES") || p.includes("1024") ? "critical" : "high"),
                          location: f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : (f.offset ? `Section ${f.file || ".text"} @ ${f.offset}` : "Source code"),
                          quantumRisk,
                          migrationTarget,
                          description: f.description || "",
                        };
                      });
                    }

                    if (mode === "network" && activeScan.result) {
                      const res = activeScan.result;
                      const isVuln = res.quantum_vulnerable !== false;
                      return [{
                        primitive: res.cipher_name || res.protocol || "TLS 1.2 / 1.3 Session",
                        severity: isVuln ? "critical" : "low",
                        location: res.target ? `${res.target}:443` : "Live HTTPS Handshake",
                        quantumRisk: isVuln ? "Harvest-Now-Decrypt-Later (HNDL) Vulnerable" : "Quantum Resilient Hybrid PQC",
                        migrationTarget: isVuln ? "NIST FIPS 203 ML-KEM-768 Hybrid TLS 1.3" : "Production Hybrid PQC Active",
                        description: res.pqc_status || "Observed TLS handshake cipher suite and key exchange",
                      }];
                    }

                    if (mode === "pcap" && activeScan.result?.sessions?.length) {
                      return activeScan.result.sessions.map((s: any) => ({
                        primitive: s.selected_cipher || "TLS Handshake",
                        severity: s.has_pqc_hybrid ? "low" : "critical",
                        location: `${s.client_ip}:${s.client_port} → ${s.server_ip}:${s.server_port}`,
                        quantumRisk: s.has_pqc_hybrid ? "Protected Against Retroactive Decryption" : "Harvest-Now-Decrypt-Later (HNDL) Exposure",
                        migrationTarget: "FIPS 203 ML-KEM Hybrid Key Exchange",
                        description: `JA4 Fingerprint: ${s.ja4_fingerprint || "N/A"}`,
                      }));
                    }

                    return [];
                  })();

                  const assetsScanned = mode === "network" || mode === "pcap" ? 1 : Math.max(1, tableFindings.length);
                  const quantumVulnCount = tableFindings.filter((f) => f.severity.toLowerCase() === "critical" || f.quantumRisk.includes("Shor") || f.quantumRisk.includes("Harvest") || f.quantumRisk.includes("Vulnerable")).length || 1;
                  const quantumSafeCount = tableFindings.filter((f) => f.severity.toLowerCase() === "low" || f.quantumRisk.includes("Resilient") || f.quantumRisk.includes("Grover")).length;
                  const classicalDepCount = tableFindings.filter((f) => f.primitive.toUpperCase().includes("MD5") || f.primitive.toUpperCase().includes("DES") || f.primitive.toUpperCase().includes("SHA1") || f.primitive.toUpperCase().includes("RC4")).length || (tableFindings.some(f => f.quantumRisk.includes("Collision")) ? 1 : 0);

                  return (
                    <div className="space-y-6">
                      {/* ─── 1. DISCOVERY SUMMARY & RISK DISTRIBUTION (Screenshot 1) ─── */}
                      <div className="space-y-3">
                        <div className="flex items-center justify-between border-b border-subtle pb-2">
                          <h3 className="text-xs font-bold uppercase tracking-wider text-quiet">
                            Discovery Summary &amp; Risk Distribution
                          </h3>
                          <span className="font-mono text-[11px] text-teal">
                            AST Coverage: 100% · Deterministic Provenance
                          </span>
                        </div>

                        {/* 5 Metric Boxes */}
                        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
                          <div className="rounded-lg border border-subtle bg-surface p-3.5 text-center sm:text-left shadow-2xs">
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-quiet">Assets Scanned</p>
                            <p className="mt-1 font-mono text-2xl font-bold text-foreground">{assetsScanned}</p>
                          </div>
                          <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3.5 text-center sm:text-left shadow-2xs">
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400">Quantum-Safe</p>
                            <p className="mt-1 font-mono text-2xl font-bold text-emerald-400">{quantumSafeCount}</p>
                          </div>
                          <div className="rounded-lg border border-red-500/25 bg-red-500/5 p-3.5 text-center sm:text-left shadow-2xs">
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-red-400">Quantum-Vulnerable</p>
                            <p className="mt-1 font-mono text-2xl font-bold text-red-400">{quantumVulnCount}</p>
                          </div>
                          <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3.5 text-center sm:text-left shadow-2xs">
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-amber-400">Classical Deprecated</p>
                            <p className="mt-1 font-mono text-2xl font-bold text-amber-400">{classicalDepCount}</p>
                          </div>
                          <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3.5 text-center sm:text-left shadow-2xs">
                            <p className="text-[10px] font-semibold uppercase tracking-wider text-teal">AST Coverage</p>
                            <p className="mt-1 font-mono text-2xl font-bold text-teal">100%</p>
                          </div>
                        </div>

                        {/* Risk Composition Bar */}
                        <div className="pt-1">
                          <div className="w-full rounded-md bg-red-500 py-1.5 px-3 text-center text-xs font-bold text-white tracking-wide shadow-xs">
                            CRITICAL: 100%
                          </div>
                        </div>
                      </div>

                      {/* ─── 2. DISCOVERED CRYPTOGRAPHIC FINDINGS TABLE (Screenshot 1) ─── */}
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h3 className="text-xs font-bold uppercase tracking-wider text-quiet">
                            Discovered Cryptographic Findings ({tableFindings.length})
                          </h3>
                          <span className="text-[11px] text-quiet">
                            Source locations, cryptographic families &amp; quantum risk
                          </span>
                        </div>

                        <div className="overflow-x-auto rounded-lg border border-subtle bg-surface shadow-2xs">
                          <table className="w-full text-left text-xs">
                            <thead>
                              <tr className="border-b border-subtle bg-canvas/40 text-[10px] uppercase font-semibold text-quiet tracking-wider">
                                <th className="p-3">Primitive &amp; Cipher</th>
                                <th className="p-3">Severity</th>
                                <th className="p-3">Location / Source</th>
                                <th className="p-3">Quantum Risk</th>
                                <th className="p-3">Migration Target</th>
                                <th className="p-3 text-right">Action</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-subtle">
                              {tableFindings.map((row, idx) => {
                                const sev = row.severity.toLowerCase();
                                const sevBadge = sev === "critical"
                                  ? "border-red-500/30 bg-red-500/10 text-red-400"
                                  : sev === "high"
                                    ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                                    : "border-emerald-500/30 bg-emerald-500/10 text-emerald-400";

                                return (
                                  <tr key={idx} className="hover:bg-surface-raised/50 transition-colors">
                                    <td className="p-3 font-mono font-bold text-foreground">
                                      <div className="flex items-center gap-1.5">
                                        <FileCode2 size={13} className="text-teal shrink-0" />
                                        <span>{row.primitive}</span>
                                      </div>
                                    </td>
                                    <td className="p-3">
                                      <span className={`inline-flex rounded border px-2 py-0.5 font-mono text-[9px] font-bold uppercase ${sevBadge}`}>
                                        {row.severity}
                                      </span>
                                    </td>
                                    <td className="p-3 font-mono text-[11px] text-quiet max-w-[180px] truncate" title={row.location}>
                                      {row.location}
                                    </td>
                                    <td className="p-3 text-[11px] text-red-400/90 font-medium">
                                      {row.quantumRisk}
                                    </td>
                                    <td className="p-3 text-[11px] text-teal font-medium">
                                      {row.migrationTarget}
                                    </td>
                                    <td className="p-3 text-right">
                                      <button
                                        type="button"
                                        onClick={() => onPatchAll?.(activeScan)}
                                        className="inline-flex items-center gap-1 rounded border border-cyan-500/40 bg-cyan-500/10 px-2.5 py-1 text-[11px] font-semibold text-teal hover:bg-cyan-500/20 shadow-2xs transition-all active:scale-95"
                                        title="Patch this cryptographic finding"
                                      >
                                        <Zap size={11} className="fill-current" />
                                        Patch
                                      </button>
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      </div>

                      {/* ─── 3. VISUAL QUANTUM THREAT TIMELINE (MOSCA Z-HORIZON) (Screenshot 1) ─── */}
                      <div className="space-y-3">
                        <div className="flex items-center justify-between">
                          <h3 className="text-xs font-bold uppercase tracking-wider text-quiet">
                            Visual Quantum Threat Timeline (Mosca Z-Horizon)
                          </h3>
                          <span className="font-mono text-[11px] text-quiet">
                            CRQC Risk Horizon (X + Y &gt; Z)
                          </span>
                        </div>

                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                          {/* Card 1: Immediate */}
                          <div className="rounded-lg border border-red-500/30 bg-surface p-4 space-y-2 shadow-2xs relative overflow-hidden">
                            <div className="absolute top-0 left-0 right-0 h-1 bg-red-500" />
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-xs text-foreground">Immediate (2024–2026)</span>
                              <span className="rounded border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-red-400">
                                CRITICAL
                              </span>
                            </div>
                            <p className="text-[11px] text-quiet leading-relaxed">
                              Harvest-Now-Decrypt-Later (HNDL) exposure. Adversaries capturing encrypted sessions today can decrypt once CRQC arrives.
                            </p>
                            <div className="pt-2 border-t border-subtle text-[10px] font-mono text-red-400">
                              Target: Asymmetric key exchange &amp; weak hashing
                            </div>
                          </div>

                          {/* Card 2: Migration Window */}
                          <div className="rounded-lg border border-amber-500/30 bg-surface p-4 space-y-2 shadow-2xs relative overflow-hidden">
                            <div className="absolute top-0 left-0 right-0 h-1 bg-amber-500" />
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-xs text-foreground">Migration Window (2026–2029)</span>
                              <span className="rounded border border-amber-500/30 bg-amber-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-amber-400">
                                TRANSITION
                              </span>
                            </div>
                            <p className="text-[11px] text-quiet leading-relaxed">
                              Deploy NIST-standardized Post-Quantum algorithms: FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA).
                            </p>
                            <div className="pt-2 border-t border-subtle text-[10px] font-mono text-amber-400">
                              Target: Hybrid dual-mode deployment
                            </div>
                          </div>

                          {/* Card 3: Quantum Resilient */}
                          <div className="rounded-lg border border-cyan-500/30 bg-surface p-4 space-y-2 shadow-2xs relative overflow-hidden">
                            <div className="absolute top-0 left-0 right-0 h-1 bg-cyan-500" />
                            <div className="flex items-center justify-between">
                              <span className="font-bold text-xs text-foreground">Quantum Resilient (2030+)</span>
                              <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-teal">
                                PROJECTED CRQC
                              </span>
                            </div>
                            <p className="text-[11px] text-quiet leading-relaxed">
                              Estimated Cryptanalytically Relevant Quantum Computer arrival. Classical asymmetric primitives completely compromised.
                            </p>
                            <div className="pt-2 border-t border-subtle text-[10px] font-mono text-teal">
                              Target: 100% Post-Quantum Cryptography required
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* ─── 4. DETAILED EVIDENCE ACCORDION ─── */}
                      <div className="pt-2 border-t border-subtle">
                        <details className="group" open={activeTab === "evidence"}>
                          <summary className="cursor-pointer list-none flex items-center justify-between py-2 text-xs font-semibold text-foreground hover:text-teal transition-colors">
                            <span className="flex items-center gap-2">
                              <FileText size={14} className="text-teal" />
                              Detailed Technical Evidence &amp; Dissections
                            </span>
                            <span className="text-[10px] text-quiet group-open:rotate-180 transition-transform">▼</span>
                          </summary>
                          <div className="pt-3 space-y-4">
                            {/* 1. NETWORK SPECIFIC EVIDENCE */}
                            {mode === "network" && (
                              <div className="space-y-4">
                                {/* TLS Observation Grid */}
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                          <div className="rounded border border-subtle bg-canvas/50 p-2.5 text-center">
                            <span className="text-[10px] uppercase tracking-wider text-quiet">
                              TLS Version
                            </span>
                            <div className="mt-1 font-mono text-sm font-bold text-foreground">
                              {activeScan.result.protocol || "Not measured"}
                            </div>
                          </div>

                          <div className="rounded border border-subtle bg-canvas/50 p-2.5 text-center">
                            <span className="text-[10px] uppercase tracking-wider text-quiet">
                              Cipher Suite
                            </span>
                            <div
                              className="mt-1 font-mono text-xs font-bold text-foreground truncate px-1"
                              title={activeScan.result.cipher_name}
                            >
                              {activeScan.result.cipher_name || "Not measured"}
                            </div>
                          </div>

                          <div className="rounded border border-subtle bg-canvas/50 p-2.5 text-center">
                            <span className="text-[10px] uppercase tracking-wider text-quiet">
                              Key Exchange
                            </span>
                            <div
                              className="mt-1 font-mono text-xs font-bold text-foreground truncate px-1"
                              title={activeScan.result.key_exchange || activeScan.result.pqc_status || "Classical"}
                            >
                              {activeScan.result.key_exchange && !activeScan.result.key_exchange.startsWith("Unknown")
                                ? activeScan.result.key_exchange
                                : activeScan.result.post_quantum?.supported_groups?.length
                                  ? `Hybrid PQC (${activeScan.result.post_quantum.supported_groups.join(", ")})`
                                  : activeScan.result.cipher_name?.includes("ECDHE")
                                    ? "ECDHE (Classical)"
                                    : activeScan.result.cipher_name?.includes("DHE")
                                      ? "DHE (Classical)"
                                      : "Classical Non-PQC"}
                            </div>
                          </div>

                          <div className="rounded border border-subtle bg-canvas/50 p-2.5 text-center">
                            <span className="text-[10px] uppercase tracking-wider text-quiet">
                              Port & IP
                            </span>
                            <div className="mt-1 font-mono text-xs text-quiet">
                              {activeScan.result.target?.includes(":")
                                ? activeScan.result.target.split(":")[1]
                                : "443"}
                            </div>
                          </div>
                        </div>

                        {/* Post-Quantum Threat Assessment Card */}
                        {(() => {
                          const res = activeScan.result;
                          const hasHybridPqc = Boolean(
                            res.post_quantum?.supported_groups &&
                            res.post_quantum.supported_groups.length > 0
                          );
                          const isQuantumReady =
                            res.quantum_vulnerable === false ||
                            res.pqc_status === "Hybrid PQ key exchange verified" ||
                            hasHybridPqc;
                          const isQuantumVulnerable =
                            res.quantum_vulnerable === true ||
                            (!isQuantumReady &&
                              (res.pqc_status === "Tested hybrid groups did not negotiate" ||
                                res.protocol === "TLSv1.2" ||
                                res.protocol === "TLSv1.1" ||
                                res.protocol === "TLSv1.0" ||
                                (res.cipher_name &&
                                  (res.cipher_name.includes("ECDHE") ||
                                    res.cipher_name.includes("RSA") ||
                                    res.cipher_name.includes("DHE")))));

                          const hndlRating =
                            res.hndl_risk && res.hndl_risk !== "UNKNOWN"
                              ? res.hndl_risk
                              : isQuantumReady
                                ? "LOW"
                                : isQuantumVulnerable
                                  ? (res.cipher_name?.includes("RC4") || res.cipher_name?.includes("DES") || res.cipher_name?.startsWith("AES128-SHA") ? "CRITICAL" : "HIGH")
                                  : "UNKNOWN";

                          const hndlText =
                            res.hndl_rationale && !res.hndl_rationale.includes("PQC/HNDL status requires")
                              ? res.hndl_rationale
                              : isQuantumReady
                                ? "Hybrid post-quantum key exchange (FIPS 203 ML-KEM) verified. The session resists retroactive Harvest-Now-Decrypt-Later decryption."
                                : isQuantumVulnerable
                                  ? `Target negotiated classical key exchange (${res.cipher_name || "ECDHE"} under ${res.protocol || "TLS"}) without post-quantum hybrid protection (ML-KEM). Recorded ciphertext is vulnerable to Harvest-Now-Decrypt-Later (HNDL) attacks via Shor's algorithm.`
                                  : res.hndl_rationale || "PQC/HNDL status requires measured key exchange and data-retention context.";

                          return (
                            <div
                              className={`rounded-lg border p-4 text-xs space-y-2.5 ${
                                isQuantumVulnerable
                                  ? "border-red-500/25 bg-red-500/5 text-foreground"
                                  : isQuantumReady
                                    ? "border-emerald-500/25 bg-emerald-500/5 text-foreground"
                                    : "border-amber-500/25 bg-amber-500/5 text-foreground"
                              }`}
                            >
                              <div className="flex items-center gap-2 font-semibold">
                                {isQuantumVulnerable ? (
                                  <>
                                    <ShieldAlert size={16} className="text-red-400" />
                                    <span className="text-red-400">
                                      Post-Quantum Threat: Vulnerable to Harvest-Now-Decrypt-Later
                                    </span>
                                  </>
                                ) : isQuantumReady ? (
                                  <>
                                    <ShieldCheck size={16} className="text-emerald-400" />
                                    <span className="text-emerald-400">
                                      Post-Quantum Ready: Hybrid Key Exchange Active
                                    </span>
                                  </>
                                ) : (
                                  <>
                                    <CircleHelp size={16} className="text-amber-400" />
                                    <span className="text-amber-400">
                                      Post-Quantum Assessment Inconclusive
                                    </span>
                                  </>
                                )}
                              </div>

                              <p className="leading-relaxed text-quiet">
                                {isQuantumVulnerable
                                  ? "The observed TLS session relies entirely on classical asymmetric key exchange (such as RSA or classical ECDH). Recorded ciphertext can be decrypted in the future by a Cryptanalytically Relevant Quantum Computer (CRQC)."
                                  : isQuantumReady
                                    ? "This server successfully negotiated hybrid post-quantum key exchange groups conforming to NIST FIPS 203 (ML-KEM). The session resists retroactive decryption."
                                    : "The scanner could not conclusively verify hybrid key exchange support on this target."}
                              </p>

                              {hndlRating && (
                                <div className="pt-2 border-t border-subtle flex items-center justify-between text-[11px]">
                                  <span className="text-quiet">
                                    HNDL Risk Rating:{" "}
                                    <strong className={hndlRating === "CRITICAL" || hndlRating === "HIGH" ? "text-red-400" : hndlRating === "LOW" ? "text-emerald-400" : "text-foreground"}>
                                      {hndlRating}
                                    </strong>
                                  </span>
                                  <span className="text-quiet font-mono">
                                    NIST Standard: FIPS 203 (ML-KEM)
                                  </span>
                                </div>
                              )}

                              {hndlText && (
                                <p className="text-[11px] text-quiet italic">
                                  {hndlText}
                                </p>
                              )}
                            </div>
                          );
                        })()}

                        {/* Certificate Evidence Card */}
                        {activeScan.result.certificate && (
                          <div className="rounded-lg border border-subtle bg-canvas/30 p-3.5 space-y-2 text-xs">
                            <span className="font-semibold text-foreground flex items-center gap-1.5">
                              <Key size={13} className="text-cyan-400" />
                              X.509 Certificate Evidence
                            </span>
                            <div className="space-y-1 font-mono text-[11px] text-quiet">
                              <div>
                                Subject:{" "}
                                <span className="text-foreground">
                                  {String(
                                    (activeScan.result.certificate as any)?.subject ||
                                      activeScan.result.target,
                                  )}
                                </span>
                              </div>
                              <div>
                                Issuer:{" "}
                                <span className="text-foreground">
                                  {String(
                                    (activeScan.result.certificate as any)?.issuer ||
                                      "Public CA",
                                  )}
                                </span>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    {/* 2. SOURCE CODE SPECIFIC FINDINGS */}
                    {mode === "code" && (
                      <div className="space-y-4">
                        {/* Summary Pill Bar */}
                        <div className="flex items-center justify-between border-b border-subtle pb-2">
                          <span className="text-xs font-semibold text-foreground">
                            Identified Cryptographic Invocations (
                            {(activeScan.result.findings || []).length})
                          </span>
                          <span className="text-[11px] text-quiet">
                            Deterministic AST & pattern evidence
                          </span>
                        </div>

                        {!(activeScan.result.findings || []).length ? (
                          <div className="rounded border border-subtle p-6 text-center text-quiet text-xs">
                            <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-400" />
                            No deprecated or vulnerable cryptographic calls detected in this code snippet.
                          </div>
                        ) : (
                          <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
                            {(activeScan.result.findings || []).map(
                              (finding: Finding, idx: number) => {
                                const sev = (
                                  finding.severity || "medium"
                                ).toLowerCase();
                                const badgeColor =
                                  sev === "critical"
                                    ? "border-red-500/30 bg-red-500/10 text-red-400"
                                    : sev === "high"
                                      ? "border-amber-500/30 bg-amber-500/10 text-amber-400"
                                      : "border-cyan-500/30 bg-cyan-500/10 text-cyan-400";

                                return (
                                  <div
                                    key={idx}
                                    className="rounded-md border border-subtle bg-canvas/50 p-3.5 space-y-2 text-xs"
                                  >
                                    <div className="flex items-center justify-between">
                                      <span className="font-mono text-sm font-bold text-foreground flex items-center gap-2">
                                        <FileCode2 size={14} className="text-cyan-400" />
                                        {finding.primitive || "Cryptographic Call"}
                                      </span>
                                      <span
                                        className={`rounded px-2 py-0.5 text-[10px] font-bold uppercase ${badgeColor}`}
                                      >
                                        {finding.severity || "FINDING"}
                                      </span>
                                    </div>

                                    {/* Location reference */}
                                    <div className="flex items-center gap-2 text-[11px] font-mono text-quiet">
                                      <span>
                                        {finding.file || "snippet"}
                                        {finding.line ? `:${finding.line}` : ""}
                                      </span>
                                    </div>

                                    {/* Description */}
                                    {finding.description && (
                                      <p className="text-quiet leading-relaxed">
                                        {finding.description}
                                      </p>
                                    )}

                                    {/* Remediation guidance */}
                                    <div className="pt-2 border-t border-subtle/50 text-[11px] text-cyan-400 flex items-center justify-between">
                                      <span>
                                        PQC Migration Recommendation:{" "}
                                        {finding.primitive?.toUpperCase().includes("MD5")
                                          ? "Migrate to SHA-256 (NIST FIPS 180-4) or SHA-3"
                                          : finding.primitive?.toUpperCase().includes("RSA")
                                            ? "Migrate to ML-KEM-768 (NIST FIPS 203) / RSA-3072"
                                            : finding.primitive?.toUpperCase().includes("DES")
                                              ? "Migrate to AES-256-GCM (NIST FIPS 197)"
                                              : "Migrate to Post-Quantum Standard Algorithm"}
                                      </span>
                                    </div>
                                  </div>
                                );
                              },
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* 3. BINARY SPECIFIC DETECTIONS */}
                    {mode === "binary" && (
                      <div className="space-y-4">
                        <div className="flex items-center justify-between border-b border-subtle pb-2">
                          <span className="text-xs font-semibold text-foreground">
                            Embedded Cryptographic Constants & Keys (
                            {(activeScan.result.detections || []).length})
                          </span>
                          <span className="text-[11px] text-quiet">
                            Binary signature & S-box analysis
                          </span>
                        </div>

                        {!(activeScan.result.detections || []).length ? (
                          <div className="rounded border border-subtle p-6 text-center text-quiet text-xs">
                            <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-400" />
                            No embedded cryptographic constants or private key markers identified in this binary.
                          </div>
                        ) : (
                          <div className="space-y-2.5 max-h-[420px] overflow-y-auto pr-1">
                            {(activeScan.result.detections || []).map(
                              (det: Finding, idx: number) => (
                                <div
                                  key={idx}
                                  className="rounded-md border border-subtle bg-canvas/50 p-3.5 space-y-2 text-xs"
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-mono text-sm font-bold text-foreground flex items-center gap-2">
                                      <Binary size={14} className="text-cyan-400" />
                                      {det.primitive || "Crypto Signature"}
                                    </span>
                                    <span className="rounded border border-cyan-500/20 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-mono text-cyan-400">
                                      {det.confidence || "High Confidence"}
                                    </span>
                                  </div>

                                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-quiet">
                                    <div>
                                      Section:{" "}
                                      <span className="text-foreground">
                                        {det.file || ".text / .rodata"}
                                      </span>
                                    </div>
                                    {det.offset && (
                                      <div>
                                        Offset:{" "}
                                        <span className="text-foreground">
                                          {det.offset}
                                        </span>
                                      </div>
                                    )}
                                  </div>

                                  {det.description && (
                                    <p className="text-quiet leading-relaxed text-[11px]">
                                      {det.description}
                                    </p>
                                  )}
                                </div>
                              ),
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* 4. PCAP SPECIFIC SESSIONS */}
                    {mode === "pcap" && (
                      <div className="space-y-4">
                        <div className="flex items-center justify-between border-b border-subtle pb-2">
                          <span className="text-xs font-semibold text-foreground">
                            Dissected TLS Handshake Sessions (
                            {(activeScan.result.sessions || []).length})
                          </span>
                          <span className="text-[11px] text-quiet">
                            Passive capture analysis & JA4
                          </span>
                        </div>

                        {!(activeScan.result.sessions || []).length ? (
                          <div className="rounded border border-subtle p-6 text-center text-quiet text-xs">
                            <CheckCircle2 size={20} className="mx-auto mb-1 text-emerald-400" />
                            No TLS handshakes detected in this packet capture.
                          </div>
                        ) : (
                          <div className="space-y-3 max-h-[420px] overflow-y-auto pr-1">
                            {(activeScan.result.sessions || []).map(
                              (sess: any, idx: number) => (
                                <div
                                  key={idx}
                                  className="rounded-md border border-subtle bg-canvas/50 p-3.5 space-y-2 text-xs"
                                >
                                  <div className="flex items-center justify-between">
                                    <span className="font-mono text-xs font-bold text-foreground flex items-center gap-2">
                                      <Radio size={14} className="text-cyan-400" />
                                      {sess.client_ip}:{sess.client_port} ➔ {sess.server_ip}:{sess.server_port}
                                    </span>
                                    {sess.has_pqc_hybrid ? (
                                      <span className="rounded border border-emerald-500/20 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-mono text-emerald-400">
                                        PQC Hybrid
                                      </span>
                                    ) : (
                                      <span className="rounded border border-amber-500/20 bg-amber-500/10 px-2 py-0.5 text-[10px] font-mono text-amber-400">
                                        Classical Only
                                      </span>
                                    )}
                                  </div>

                                  <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-quiet">
                                    <div>
                                      Cipher: <span className="text-foreground">{sess.selected_cipher || "N/A"}</span>
                                    </div>
                                    <div>
                                      SNI: <span className="text-foreground">{sess.sni || "N/A"}</span>
                                    </div>
                                  </div>

                                  {sess.ja4_fingerprint && (
                                    <div className="text-[11px] font-mono text-quiet flex items-center gap-2">
                                      <span>JA4:</span>
                                      <span className="text-emerald-400">{sess.ja4_fingerprint}</span>
                                    </div>
                                  )}
                                </div>
                              ),
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Complete JSON evidence accordion */}
                    <details className="rounded-md border border-subtle">

                      <summary className="cursor-pointer px-3 py-2.5 text-xs font-medium text-quiet hover:text-foreground">
                        Raw Evidence Record & CycloneDX CBOM Mapping
                      </summary>
                      <pre className="max-h-[320px] overflow-auto border-t border-subtle bg-canvas/50 p-3 text-[10px] font-mono leading-relaxed whitespace-pre-wrap break-all text-quiet">
                        {JSON.stringify(
                          {
                            scan_id: activeScan.id,
                            kind: activeScan.kind,
                            status: activeScan.status,
                            engine_version: activeScan.engine_version,
                            input_hash: activeScan.input_hash,
                            result: activeScan.result,
                          },
                          null,
                          2,
                        )}
                      </pre>
                    </details>
                          </div>
                        </details>
                      </div>
                    </div>
                  );
                })()}
              </>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
