"use client";

import { useCallback, useEffect, useState } from "react";
import {
  Activity,
  Binary,
  Code2,
  Download,
  Globe,
  ShieldCheck,
  RefreshCw,
  ChevronRight,
  ArrowRight,
  Upload,
  FolderOpen,
  FileCode2,
  History,
  CheckCircle2,
  CircleHelp,
  Settings2,
  Search,
  X,
  LoaderCircle,
  AlertTriangle,
} from "lucide-react";
import { requestApi, Scan } from "@/lib/api";
import Link from "next/link";
import { ThemeToggle } from "@/components/ecdat/theme-toggle";
import { Overview } from "@/components/ecdat/overview";
import { MigrationPlanner } from "@/components/ecdat/migration-planner";
import { LayoutDashboard, Route, FlaskConical, Scale, FileCheck2, PlayCircle, Radio, Wrench } from "lucide-react";
import { VerificationPanel } from "@/components/ecdat/verification-panel";
import { StandardsPanel } from "@/components/ecdat/standards-panel";
import { ExperimentalHub } from "@/components/ecdat/experimental-hub";
import { SihDemoPanel } from "@/components/ecdat/sih-demo-panel";
import { JudgeDemoPanel } from "@/components/ecdat/judge-demo-panel";
import { FeatureScanHistory } from "@/components/ecdat/feature-scan-history";
import { AutonomousLoopPanel } from "@/components/ecdat/autonomous-loop-panel";

const inputClass =
  "w-full min-w-0 rounded-md border border-subtle bg-canvas px-3 py-2.5 text-sm text-foreground placeholder:text-quiet outline-none transition-colors focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/15";
const buttonClass = "ec-button";
const panelClass = "min-w-0 rounded-lg border border-subtle bg-surface";
const scanTypes = [
  {
    id: "network",
    label: "Network scan",
    description: "Websites & servers",
    icon: Globe,
    title: "Check a website or server",
    help: "Inspect its secure connection, supported encryption, and certificate.",
    checks: [
      "TLS versions and encryption",
      "Certificate validity and trust",
      "Measured connection details",
    ],
  },
  {
    id: "code",
    label: "Code scan",
    description: "Files, folders & snippets",
    icon: Code2,
    title: "Find cryptography in your code",
    help: "Paste a snippet or upload source files to find cryptographic usage.",
    checks: [
      "Cryptographic calls and weak algorithms",
      "File and line references",
      "Analysis coverage and skipped files",
    ],
  },
  {
    id: "binary",
    label: "Binary & firmware",
    description: "Compiled files & ZIPs",
    icon: Binary,
    title: "Inspect a binary or firmware file",
    help: "Upload a file to find cryptographic signatures and embedded key material.",
    checks: [
      "Cryptographic constants and keys",
      "ELF / PE file sections",
      "ZIP contents and scan coverage",
    ],
  },
  {
    id: "pcap",
    label: "Passive PCAP",
    description: "Packet captures & dumps",
    icon: Radio,
    title: "Inspect packet captures & TLS sessions",
    help: "Upload a PCAP capture file or analyze synthetic PQC traffic to dissect TLS handshakes and JA3/JA4 fingerprints without active probing.",
    checks: [
      "ClientHello & ServerHello dissection",
      "FIPS 203 ML-KEM hybrid key exchange",
      "JA3 & JA4 fingerprint extraction",
    ],
  },
] as const;

const kindLabels: Record<string, string> = {
  network: "Network",
  code: "Code",
  binary: "Binary",
  pcap: "Passive PCAP",
};
const languageLabels: Record<string, string> = {
  python: "Python",
  java: "Java",
  c_cpp: "C / C++",
  golang: "Go",
  javascript: "JavaScript / TypeScript",
};

function scanLabel(scan: Scan) {
  const matches = scan.result?.findings || scan.result?.detections || [];
  return (
    scan.result?.target ||
    matches[0]?.file ||
    `${kindLabels[scan.kind]} scan · ${scan.id.slice(0, 8)}`
  );
}

function StatusBadge({ status }: { status: Scan["status"] }) {
  const color =
    status === "completed"
      ? "border-emerald-500/20 bg-emerald-500/10 text-success"
      : status === "failed"
        ? "border-red-500/20 bg-red-500/10 text-danger"
        : status === "cancelled"
          ? "border-slate-500/20 bg-slate-500/10 text-quiet"
          : "border-cyan-500/20 bg-cyan-500/10 text-teal";
  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded border px-2 py-1 text-[11px] font-medium ${color}`}
    >
      {status === "running" && (
        <LoaderCircle size={11} className="motion-safe:animate-spin" />
      )}
      {
        {
          completed: "Completed",
          failed: "Failed",
          cancelled: "Cancelled",
          running: "Scanning",
          queued: "Waiting",
        }[status]
      }
    </span>
  );
}
const languageExtensions: Record<string, string> = {
  python: "py",
  java: "java",
  c_cpp: "cpp",
  golang: "go",
  javascript: "js",
};

export default function Dashboard() {
  const [view, setView] = useState<
    "overview" | "scans" | "history" | "migration" | "verification" | "standards" | "experimental" | "sih_demo" | "judge_demo" | "patch_migration"
  >("overview");
  const [projectInput, setProjectInput] = useState("default");
  const [project, setProject] = useState("default");
  const [token, setToken] = useState("");
  const [nvidiaKey, setNvidiaKey] = useState("");
  const [mode, setMode] = useState<"network" | "code" | "binary" | "pcap">("network");
  const [target, setTarget] = useState("");
  const [language, setLanguage] = useState("python");
  const [code, setCode] = useState("");
  const [sourceFiles, setSourceFiles] = useState<File[]>([]);
  const [binary, setBinary] = useState<File | null>(null);
  const [pcapFile, setPcapFile] = useState<File | null>(null);
  const [pcapPqcHybrid, setPcapPqcHybrid] = useState(true);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [connected, setConnected] = useState(false);
  const [exportIds, setExportIds] = useState<string[]>([]);
  const [historyFilter, setHistoryFilter] = useState<"all" | Scan["kind"]>(
    "all",
  );

  useEffect(() => {
    if (typeof window !== "undefined") {
      const savedKey = localStorage.getItem("ecdat_nvidia_api_key");
      if (savedKey) setNvidiaKey(savedKey);
    }

    function readHash() {
      const hash = window.location.hash.slice(1);
      if (hash === "migration") setView("migration");
      else if (hash === "verify" || hash === "verification") setView("verification");
      else if (hash === "patch" || hash === "autopatch" || hash === "patch_migration" || hash === "codebase-patch") setView("patch_migration");
      else if (hash === "standards") setView("standards");
      else if (hash === "experimental") setView("experimental");
      else if (hash === "sih_demo" || hash === "sih-demo") setView("sih_demo");
      else if (hash === "judge_demo" || hash === "judge-demo" || hash === "live-demo") setView("judge_demo");
      else if (hash === "history") setView("history");
      else if (["network", "code", "binary", "pcap"].includes(hash)) {
        setMode(hash as "network" | "code" | "binary" | "pcap");
        setView("scans");
      }
    }

    readHash();
    window.addEventListener("hashchange", readHash);
    return () => window.removeEventListener("hashchange", readHash);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const records = await requestApi<Scan[]>("/scans", project, token);
      setScans(records);
      setConnected(true);
    } catch (err) {
      setConnected(false);
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [project, token]);

  useEffect(() => {
    let active = true;
    let timer: ReturnType<typeof setTimeout>;
    const update = async () => {
      try {
        const records = await requestApi<Scan[]>("/scans", project, token);
        if (active) {
          setScans(records);
          setConnected(true);
        }
      } catch (err) {
        if (active) {
          setConnected(false);
          setError(err instanceof Error ? err.message : String(err));
        }
      } finally {
        if (active) timer = setTimeout(() => void update(), 2500);
      }
    };
    void update();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [project, token]);

  async function submit() {
    setBusy(true);
    setError("");
    try {
      let path: string;
      let body: unknown;
      if (mode === "network") {
        if (!target.trim()) throw new Error("Enter a hostname or HTTPS URL.");
        path = "/scan/network";
        body = { target: target.trim() };
      } else if (mode === "binary") {
        if (!binary) throw new Error("Choose a binary or ZIP file.");
        if (binary.size === 0 || binary.size > 8 * 1024 * 1024)
          throw new Error("Upload must contain 1 byte to 8 MiB.");
        path = "/scan/binary/upload";
        const form = new FormData();
        form.append("file", binary);
        body = form;
      } else if (mode === "pcap") {
        if (pcapFile) {
          if (pcapFile.size === 0 || pcapFile.size > 8 * 1024 * 1024)
            throw new Error("PCAP file must contain 1 byte to 8 MiB.");
          path = "/scan/pcap/upload";
          const form = new FormData();
          form.append("file", pcapFile);
          body = form;
        } else {
          path = "/scan/pcap/synthetic";
          body = { with_pqc_hybrid: pcapPqcHybrid };
        }
      } else {

        if (!sourceFiles.length && !code.trim())
          throw new Error("Paste code or choose source files.");

        const MAX_SOURCE_BYTES = 500 * 1024 * 1024; // 500 MB
        const MAX_SOURCE_FILES = 10000;
        const totalSize = sourceFiles.reduce((sum, f) => sum + f.size, 0);

        if (sourceFiles.length > MAX_SOURCE_FILES || totalSize > MAX_SOURCE_BYTES) {
          throw new Error(
            `Choose at most ${MAX_SOURCE_FILES.toLocaleString()} source files totaling 500 MB. (Selected: ${sourceFiles.length} files, ${(totalSize / (1024 * 1024)).toFixed(1)} MB)`
          );
        }

        if (sourceFiles.length > 0) {
          const isArchive =
            sourceFiles.length === 1 &&
            /\.(zip|tar\.gz|tgz|tar)$/i.test(sourceFiles[0].name);

          // For small source folder/files under 15MB, encode as base64 in JSON
          // to completely bypass WAF multipart / code-injection inspection.
          if (!isArchive && totalSize < 15 * 1024 * 1024) {
            path = "/scan/sources";
            const encodedFiles = await Promise.all(
              sourceFiles.map(async (file) => {
                const buf = await file.arrayBuffer();
                const bytes = new Uint8Array(buf);
                let bin = "";
                for (let i = 0; i < bytes.length; i++) {
                  bin += String.fromCharCode(bytes[i]);
                }
                return {
                  path: (file.webkitRelativePath || file.name).replace(/\\/g, "/"),
                  content_b64: btoa(bin),
                };
              })
            );
            body = { files: encodedFiles };
          } else {
            path = "/scan/sources/upload";
            const formData = new FormData();
            if (isArchive) {
              formData.append("file", sourceFiles[0]);
            } else {
              for (const file of sourceFiles) {
                formData.append("files", file, file.webkitRelativePath || file.name);
              }
            }
            body = formData;
          }
        } else {
          path = "/scan/sources";
          // Base64-encode code snippet to prevent Cloudflare WAF / firewall inspection blocks
          const utf8Bytes = new TextEncoder().encode(code);
          let binary = "";
          for (let i = 0; i < utf8Bytes.length; i++) {
            binary += String.fromCharCode(utf8Bytes[i]);
          }
          const codeB64 = btoa(binary);

          body = {
            files: [
              {
                path: `snippet.${languageExtensions[language] || "js"}`,
                content_b64: codeB64,
                language,
              },
            ],
          };
        }
      }
      const scan = await requestApi<Scan>(path, project, token, body);
      setSelected(scan.id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function download() {
    setError("");
    try {
      const data = await requestApi("/export/cbom", project, token, {
        scan_ids: exportIds,
        target_name: project,
      });
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = `${project}-cbom.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function downloadSingle(scan: Scan) {
    setError("");
    try {
      const label = scanLabel(scan).replace(/[^a-zA-Z0-9_-]/g, "_");
      const data = await requestApi("/export/cbom", project, token, {
        scan_ids: [scan.id],
        target_name: `${project}-${label}`,
      });
      const url = URL.createObjectURL(
        new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }),
      );
      const link = document.createElement("a");
      link.href = url;
      link.download = `${project}-${label}-cbom.json`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  const featureScans = scans.filter((scan) => scan.kind === mode);
  const historyCurrent = scans.find((s) => s.id === selected);
  const completed = featureScans.filter((s) => s.status === "completed");
  const running = featureScans.filter((s) =>
    ["queued", "running"].includes(s.status),
  );
  const historyScans =
    historyFilter === "all"
      ? scans
      : scans.filter((scan) => scan.kind === historyFilter);

  const activeType = scanTypes.find((type) => type.id === mode)!;
  const failed = featureScans.filter((scan) => scan.status === "failed");

  return (
    <div className="workspace-shell min-h-screen bg-canvas text-foreground lg:flex">
      <aside className="border-b border-subtle bg-surface lg:sticky lg:top-0 lg:flex lg:h-dvh lg:w-60 lg:shrink-0 lg:flex-col lg:border-b-0 lg:border-r">
        <div className="flex items-center gap-3 border-b border-subtle px-5 py-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/25 bg-cyan-500/10">
            <ShieldCheck className="text-teal" size={21} />
          </div>
          <div>
            <Link href="/" className="text-base font-bold tracking-tight">
              ECDAT
            </Link>
            <p className="mt-0.5 text-[10px] uppercase tracking-widest text-quiet">
              Cryptographic discovery
            </p>
          </div>
          <span className="ml-auto rounded border border-subtle px-1.5 py-0.5 font-mono text-[10px] text-quiet">
            v3
          </span>
        </div>
        <nav aria-label="Workspace navigation" className="overflow-y-auto p-3 lg:flex-1">
          <p className="nav-group-label">Overview</p>
          <div className="mb-4 grid grid-cols-2 gap-1 lg:grid-cols-1">
            <button
              onClick={() => setView("overview")}
              aria-current={view === "overview" ? "page" : undefined}
              className={`flex items-center gap-3 rounded-md border px-3 py-3 text-xs font-semibold ${view === "overview" ? "border-subtle bg-surface-raised text-foreground" : "border-transparent text-quiet hover:bg-surface-raised"}`}
            >
              <LayoutDashboard size={16} />
              Command center
            </button>
          </div>
          <p className="nav-group-label">Discovery</p>
          <div className="grid grid-cols-3 gap-1 lg:grid-cols-1 lg:gap-1.5">
            {scanTypes.map(({ id, label, description, icon: Icon }) => (
              <button
                key={id}
                onClick={() => {
                  setMode(id);
                  setView("scans");
                }}
                aria-current={
                  view === "scans" && mode === id ? "page" : undefined
                }
                className={`group flex min-w-0 items-center justify-center gap-2 rounded-md border px-2 py-3 text-left transition-colors focus-visible:outline-2 focus-visible:outline-cyan-400 lg:justify-start lg:px-3 ${view === "scans" && mode === id ? "border-cyan-500/20 bg-cyan-500/10 text-teal" : "border-transparent text-quiet hover:bg-surface-raised hover:text-foreground"}`}
              >
                <Icon size={16} className="hidden shrink-0 min-[400px]:block" />
                <span className="min-w-0">
                  <span className="block text-xs font-semibold">{label}</span>
                  <span className="mt-1 hidden text-[10px] text-quiet lg:block">
                    {description}
                  </span>
                </span>
                {view === "scans" && mode === id && (
                  <ChevronRight
                    size={13}
                    className="ml-auto hidden shrink-0 lg:block"
                  />
                )}
              </button>
            ))}
          </div>
          <p className="nav-group-label nav-group-action">Action & Verification</p>
          <button
            onClick={() => setView("migration")}
            aria-current={view === "migration" ? "page" : undefined}
            className={`flex w-full items-center gap-3 rounded-md border px-3 py-2.5 text-left text-xs font-semibold ${view === "migration" ? "border-cyan-500/20 bg-cyan-500/10 text-teal" : "border-transparent text-quiet hover:bg-surface-raised hover:text-foreground"}`}
          >
            <Route size={16} />
            Migration planner
          </button>
          <button
            onClick={() => setView("verification")}
            aria-current={view === "verification" ? "page" : undefined}
            className={`mt-1.5 flex w-full items-center gap-3 rounded-md border px-3 py-2.5 text-left text-xs font-semibold ${view === "verification" ? "border-cyan-500/20 bg-cyan-500/10 text-teal" : "border-transparent text-quiet hover:bg-surface-raised hover:text-foreground"}`}
          >
            <FileCheck2 size={16} />
            Verification engine
          </button>
          <button
            onClick={() => setView("patch_migration")}
            aria-current={view === "patch_migration" ? "page" : undefined}
            className={`mt-1.5 flex w-full items-center gap-2.5 rounded-md border px-3 py-2.5 text-left text-xs font-semibold ${view === "patch_migration" ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300" : "border-transparent text-quiet hover:bg-surface-raised hover:text-foreground"}`}
          >
            <Wrench size={16} className="shrink-0 text-emerald-400" />
            <span>Codebase Auto-Patcher</span>
            <span className="ml-auto rounded bg-emerald-500/20 px-1.5 py-0.5 font-mono text-[9px] text-emerald-300">
              Full-Zip
            </span>
          </button>
          <p className="nav-group-label nav-group-action">Compliance</p>
          <button
            onClick={() => setView("standards")}
            aria-current={view === "standards" ? "page" : undefined}
            className={`flex w-full items-center gap-3 rounded-md border px-3 py-2.5 text-left text-xs font-semibold ${view === "standards" ? "border-cyan-500/20 bg-cyan-500/10 text-teal" : "border-transparent text-quiet hover:bg-surface-raised hover:text-foreground"}`}
          >
            <Scale size={16} />
            Standards & mandates
          </button>
          <p className="nav-group-label nav-group-action">Innovations</p>
          <button
            onClick={() => setView("experimental")}
            aria-current={view === "experimental" ? "page" : undefined}
            className={`flex w-full items-center gap-3 rounded-md border px-3 py-2.5 text-left text-xs font-semibold ${view === "experimental" ? "border-cyan-500/20 bg-cyan-500/10 text-teal" : "border-transparent text-quiet hover:bg-surface-raised hover:text-foreground"}`}
          >
            <FlaskConical size={16} />
            Experimental hub
          </button>
          <button
            onClick={() => setView("sih_demo")}
            aria-current={view === "sih_demo" ? "page" : undefined}
            className={`mt-1.5 flex w-full items-center gap-3 rounded-md border border-cyan-500/30 bg-cyan-500/10 px-3 py-2.5 text-left text-xs font-semibold text-teal hover:bg-cyan-500/20`}
          >
            <PlayCircle size={16} className="text-teal" />
            SIH 10-step demo
          </button>
          <button
            onClick={() => setView("judge_demo")}
            aria-current={view === "judge_demo" ? "page" : undefined}
            className={`mt-1.5 flex w-full items-center gap-2.5 rounded-md border border-emerald-500/40 bg-emerald-500/15 px-3 py-2.5 text-left text-xs font-semibold text-emerald-300 hover:bg-emerald-500/25 shadow-sm transition-all`}
          >
            <ShieldCheck size={16} className="text-emerald-400 shrink-0" />
            <span>Live Website Patch Demo</span>
            <span className="ml-auto rounded bg-emerald-500/20 px-1.5 py-0.5 font-mono text-[9px] text-emerald-300 uppercase">
              Judge
            </span>
          </button>
          <p className="nav-group-label nav-group-action">Reports</p>
          <button
            onClick={() => setView("history")}
            aria-current={view === "history" ? "page" : undefined}
            className={`mt-1.5 hidden w-full items-center gap-3 rounded-md px-3 py-2.5 text-left text-xs font-medium lg:flex ${view === "history" ? "bg-cyan-500/10 text-teal" : "text-quiet hover:bg-surface-raised hover:text-foreground"}`}
          >
            <History size={16} />
            History & reports
            <span className="ml-auto rounded bg-surface-raised px-1.5 py-0.5 font-mono text-[10px]">
              {scans.length}
            </span>
          </button>
        </nav>
        <div className="border-t border-subtle p-4">
          <details className="group" open>
            <summary className="mb-3 flex cursor-pointer list-none items-center gap-2 text-[11px] font-semibold uppercase tracking-wider text-quiet">
              <FolderOpen size={13} />
              Project
              <ChevronRight
                size={12}
                className="ml-auto transition-transform group-open:rotate-90"
              />
            </summary>
            <div className="flex gap-2">
              <input
                aria-label="Project"
                className={`${inputClass} !text-xs`}
                value={projectInput}
                onChange={(e) => setProjectInput(e.target.value)}
              />
              <button
                aria-label="Open project"
                title="Open project"
                className={`${buttonClass} !px-2.5`}
                disabled={busy}
                onClick={() => {
                  if (!/^[A-Za-z0-9_-]{1,64}$/.test(projectInput)) {
                    setError(
                      "Use 1–64 letters, numbers, underscores or hyphens for project.",
                    );
                    return;
                  }
                  setProject(projectInput);
                  setScans([]);
                  setSelected(null);
                  setExportIds([]);
                  setError("");
                }}
              >
                <ArrowRight size={15} />
              </button>
            </div>
            <p className="mt-2 text-[11px] leading-relaxed text-quiet">
              Keep related scans together in a project.
            </p>
          </details>
          <details className="mt-4 border-t border-subtle pt-3">
            <summary className="flex cursor-pointer list-none items-center gap-2 text-xs text-quiet">
              <Settings2 size={13} />
              Connection settings
            </summary>
            <label className="mt-3 block text-xs text-quiet">
              Access token
              <input
                type="password"
                autoComplete="off"
                aria-label="Backend access token"
                placeholder="Only if required"
                className={`${inputClass} mt-2 !text-xs`}
                value={token}
                onChange={(e) => {
                  setToken(e.target.value);
                  setError("");
                }}
              />
            </label>
            <label className="mt-3 block text-xs text-quiet">
              NVIDIA NIM API Key (DeepSeek-R1)
              <input
                type="password"
                autoComplete="off"
                aria-label="NVIDIA NIM API Key"
                placeholder="nvapi-... (for DeepSeek-R1 PQC Refactoring)"
                className={`${inputClass} mt-2 !text-xs font-mono`}
                value={nvidiaKey}
                onChange={(e) => {
                  setNvidiaKey(e.target.value);
                  if (typeof window !== "undefined") {
                    localStorage.setItem("ecdat_nvidia_api_key", e.target.value.trim());
                  }
                }}
              />
            </label>
            <p className="mt-2 text-[11px] leading-relaxed text-quiet">
              Kept only for this page session. Projects share the same access
              token and NVIDIA NIM key.
            </p>
          </details>
        </div>
      </aside>

      <main className="min-w-0 flex-1">
        <header className="flex min-h-16 flex-wrap items-center justify-between gap-3 border-b border-subtle bg-surface/40 px-5 py-3 lg:px-7">
          <div className="flex min-w-0 items-center gap-2 text-xs">
            <span className="text-quiet">Workspace</span>
            <ChevronRight size={12} className="text-quiet" />
            <span className="font-semibold">
              {view === "overview"
                ? "Command center"
                : view === "migration"
                  ? "Migration planner"
                  : view === "verification"
                    ? "Closed-loop verification"
                    : view === "patch_migration"
                      ? "Full Codebase Post-Quantum Patch Migration"
                      : view === "standards"
                        ? "Standards & regulatory mapping"
                        : view === "experimental"
                          ? "Experimental extensions (A–G)"
                          : view === "sih_demo"
                            ? "SIH 10-step interactive demo"
                            : view === "history"
                              ? "History & reports"
                              : activeType.label}
            </span>
          </div>
          <div className="flex items-center gap-3">
            <ThemeToggle />
            <span className="hidden rounded border border-subtle px-2 py-1 font-mono text-[10px] text-quiet sm:block">
              CycloneDX 1.6
            </span>
            <span
              role="status"
              className={`flex items-center gap-1.5 rounded border px-2 py-1 text-[10px] font-medium ${connected ? "border-emerald-500/20 bg-emerald-500/10 text-success" : "border-amber-500/20 bg-amber-500/10 text-warning"}`}
            >
              <span
                className={`h-1.5 w-1.5 rounded-full ${connected ? "bg-emerald-400" : "bg-amber-400"}`}
              />
              {connected ? "Connected" : "Not connected"}
            </span>
          </div>
        </header>
        <div className="mx-auto max-w-[1500px] space-y-6 p-4 sm:p-6 lg:p-7">
          {view === "overview" && (
            <Overview
              scans={scans}
              connected={connected}
              onStart={(kind) => {
                setMode(kind);
                setView("scans");
              }}
              onInspect={(id) => {
                const targetScan = scans.find((s) => s.id === id);
                if (targetScan) {
                  if (
                    targetScan.kind === "network" ||
                    targetScan.kind === "code" ||
                    targetScan.kind === "binary" ||
                    targetScan.kind === "pcap"
                  ) {
                    setMode(targetScan.kind);
                  }

                }
                setSelected(id);
                setView("scans");
              }}
              onMigration={() => setView("migration")}
              onVerification={() => setView("verification")}
              onStandards={() => setView("standards")}
              onExperimental={() => setView("experimental")}
              onSihDemo={() => setView("sih_demo")}
              onPatchMigration={() => setView("patch_migration")}
            />
          )}
          {view === "migration" && (
            <MigrationPlanner
              key={project + ":" + token}
              scans={scans}
              project={project}
              token={token}
              onScan={() => {
                setMode("network");
                setView("scans");
              }}
            />
          )}
          {view === "verification" && (
            <VerificationPanel project={project} token={token} />
          )}
          {view === "patch_migration" && (
            <AutonomousLoopPanel project={project} token={token} />
          )}
          {view === "standards" && (
            <StandardsPanel project={project} token={token} />
          )}
          {view === "experimental" && (
            <ExperimentalHub project={project} token={token} />
          )}
          {view === "sih_demo" && (
            <SihDemoPanel project={project} token={token} />
          )}
          {view === "judge_demo" && (
            <JudgeDemoPanel project={project} token={token} />
          )}
          {view !== "scans" && error && (
            <div role="alert" className="ec-alert">
              <AlertTriangle size={16} />
              {error}
            </div>
          )}
          {view === "scans" && (
            <>
              <div className="flex flex-wrap items-end justify-between gap-3">
                <div>
                  <p className="mb-1.5 text-[10px] uppercase tracking-[0.18em] text-teal">
                    {project} / scan workspace
                  </p>
                  <h2 className="text-xl font-semibold tracking-tight sm:text-2xl">
                    {activeType.title}
                  </h2>
                  <p className="mt-2 text-sm text-quiet">{activeType.help}</p>
                </div>
                <button
                  onClick={() => setView("history")}
                  className="flex items-center gap-1.5 py-2 text-xs text-quiet hover:text-teal"
                >
                  <History size={14} />
                  View all scan history
                  <ArrowRight size={12} />
                </button>
              </div>
              {error && (
                <div
                  role="alert"
                  className="flex items-start gap-3 rounded-md border border-red-500/25 bg-red-500/10 p-3 text-sm text-danger"
                >
                  <AlertTriangle size={16} className="mt-0.5 shrink-0" />
                  <span className="min-w-0 flex-1 break-words">{error}</span>
                  <button
                    onClick={() => setError("")}
                    aria-label="Dismiss error"
                    className="p-1"
                  >
                    <X size={15} />
                  </button>
                </div>
              )}
              <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
                {[
                  {
                    label: "Completed scans",
                    count: completed.length,
                    Icon: CheckCircle2,
                    color: "text-success",
                    note: "Saved in this project",
                  },
                  {
                    label: "In progress",
                    count: running.length,
                    Icon: Activity,
                    color: "text-teal",
                    note: "Waiting or scanning",
                  },
                  {
                    label: "Failed scans",
                    count: failed.length,
                    Icon: AlertTriangle,
                    color: "text-warning",
                    note: "Open a scan for details",
                  },
                  {
                    label: "Selected for report",
                    count: exportIds.length,
                    Icon: Download,
                    color: "text-teal",
                    note: "Choose scans below",
                  },
                ].map(({ label, count, Icon, color, note }) => (
                  <div key={label} className={`${panelClass} p-4`}>
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-[11px] text-quiet">{label}</p>
                      <Icon size={15} className={color} />
                    </div>
                    <p className="mt-2 font-mono text-2xl font-semibold">
                      {count}
                    </p>
                    <p className="mt-1 text-[10px] text-quiet">{note}</p>
                  </div>
                ))}
              </div>

              <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1fr)_260px]">
                <section
                  className={panelClass}
                  aria-labelledby="new-scan-heading"
                >
                  <div className="flex items-center justify-between border-b border-subtle px-5 py-3.5">
                    <h3
                      id="new-scan-heading"
                      className="flex items-center gap-2 text-sm font-semibold"
                    >
                      <span className="flex h-5 w-5 items-center justify-center rounded border border-cyan-500/25 bg-cyan-500/10 text-[10px] text-teal">
                        1
                      </span>
                      Start a new scan
                    </h3>
                    <span className="text-[10px] text-quiet">
                      {activeType.label}
                    </span>
                  </div>
                  <div className="space-y-4 p-5">
                    {mode === "network" && (
                      <>
                        <label className="block text-xs font-medium text-foreground">
                          Website or server address
                          <input
                            aria-label="Hostname or URL"
                            className={`${inputClass} mt-2 font-mono`}
                            placeholder="example.org or https://example.org:8443"
                            value={target}
                            onChange={(e) => setTarget(e.target.value)}
                          />
                        </label>
                        <p className="text-xs leading-relaxed text-quiet">
                          Enter a domain or full URL. Include a port if your
                          server uses one.
                        </p>
                      </>
                    )}
                    {mode === "code" && (
                      <>
                        <div className="grid gap-3 sm:grid-cols-2">
                          <label className="block min-w-0 rounded-md border border-subtle bg-canvas/50 p-3 text-xs text-foreground">
                            <span className="flex items-center gap-2">
                              <FileCode2 size={14} className="text-teal" />
                              Choose files
                            </span>
                            <input
                              type="file"
                              multiple
                              aria-label="Source files"
                              className="mt-3 block w-full min-w-0 text-[11px] text-quiet file:mr-2 file:rounded file:border-0 file:bg-surface-raised file:px-2 file:py-1.5 file:text-foreground"
                              onChange={(e) =>
                                setSourceFiles(Array.from(e.target.files || []))
                              }
                            />
                          </label>
                          <label className="block min-w-0 rounded-md border border-subtle bg-canvas/50 p-3 text-xs text-foreground">
                            <span className="flex items-center gap-2">
                              <FolderOpen size={14} className="text-teal" />
                              Choose a folder
                            </span>
                            <span className="mt-1 block text-[10px] text-quiet">
                              Select a source folder to include its files.
                            </span>
                            <span className="mt-3 inline-flex rounded bg-surface-raised px-2 py-1.5 text-[11px] font-medium text-foreground">
                              Choose folder
                            </span>
                            <input
                              type="file"
                              multiple
                              {...{ webkitdirectory: "" }}
                              aria-label="Choose source folder"
                              className="sr-only"
                              onChange={(e) =>
                                setSourceFiles(Array.from(e.target.files || []))
                              }
                            />
                          </label>
                        </div>
                        <div className="flex items-center justify-between gap-2 rounded-md border border-subtle bg-canvas/40 p-2.5 text-xs text-quiet">
                          <span className="flex items-center gap-1.5">
                            <span className="text-teal font-semibold">GitHub Integration:</span>
                            Pull public or private repos directly into ECDAT.
                          </span>
                          <button
                            type="button"
                            onClick={() => setView("patch_migration")}
                            className="rounded bg-teal/15 px-2.5 py-1 text-[11px] font-semibold text-teal hover:bg-teal/25 transition-colors"
                          >
                            Pull from GitHub →
                          </button>
                        </div>
                        {sourceFiles.length > 0 ? (
                          <div className="flex items-center justify-between gap-2 rounded-md border border-cyan-500/20 bg-cyan-500/5 p-3 text-xs text-teal">
                            <span>
                              {sourceFiles.length}{" "}
                              {sourceFiles.length === 1 ? "file" : "files"} (
                              {(
                                sourceFiles.reduce((sum, f) => sum + f.size, 0) /
                                (1024 * 1024)
                              ).toFixed(1)}{" "}
                              MB / 500 MB limit) ready to scan
                            </span>
                            <button
                              className="text-quiet underline underline-offset-4"
                              onClick={() => setSourceFiles([])}
                            >
                              Use pasted code instead
                            </button>
                          </div>
                        ) : (
                          <>
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <label
                                htmlFor="source-code"
                                className="text-xs font-medium text-foreground"
                              >
                                Or paste your code
                              </label>
                              <select
                                aria-label="Snippet language"
                                className={`${inputClass} !w-auto !py-1.5 !text-xs`}
                                value={language}
                                onChange={(e) => setLanguage(e.target.value)}
                              >
                                {Object.keys(languageExtensions).map((lang) => (
                                  <option key={lang} value={lang}>
                                    {languageLabels[lang]}
                                  </option>
                                ))}
                              </select>
                            </div>
                            <div className="flex flex-wrap items-center gap-1.5 pt-0.5">
                              <span className="text-[11px] font-medium text-quiet">Judge demo presets:</span>
                              <button
                                type="button"
                                onClick={async () => {
                                  try {
                                    const res = await requestApi<{ content: string; language: string }>("/demo/target/source?target=apex_pay", project, token);
                                    setCode(res.content);
                                    setLanguage("javascript");
                                  } catch {
                                    setCode(`// ApexPay Payment Gateway (Vulnerable: MD5 + DES)\nconst crypto = require('crypto');\nfunction hashPassword(password) {\n  return crypto.createHash('md5').update(password).digest('hex');\n}\nfunction encryptCard(cardNumber, key) {\n  const cipher = crypto.createCipheriv('des-ecb', key, null);\n  return Buffer.concat([cipher.update(cardNumber, 'utf8'), cipher.final()]).toString('base64');\n}\n`);
                                    setLanguage("javascript");
                                  }
                                }}
                                className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 text-[10px] font-medium text-teal hover:bg-cyan-500/20 transition-colors"
                              >
                                ⚡ ApexPay (MD5 & DES)
                              </button>
                              <button
                                type="button"
                                onClick={async () => {
                                  try {
                                    const res = await requestApi<{ content: string; language: string }>("/demo/target/source?target=med_vault", project, token);
                                    setCode(res.content);
                                    setLanguage("javascript");
                                  } catch {
                                    setCode(`// MedVault Healthcare Portal (Vulnerable: RSA-1024)\nconst crypto = require('crypto');\nfunction generateDoctorPrescriptionKey() {\n  return crypto.generateKeyPairSync('rsa', {\n    modulusLength: 1024,\n    publicKeyEncoding: { type: 'spki', format: 'pem' },\n    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }\n  });\n}\n`);
                                    setLanguage("javascript");
                                  }
                                }}
                                className="rounded border border-purple-500/30 bg-purple-500/10 px-2 py-0.5 text-[10px] font-medium text-purple-300 hover:bg-purple-500/20 transition-colors"
                              >
                                ⚡ MedVault (RSA-1024)
                              </button>
                              <button
                                type="button"
                                onClick={async () => {
                                  try {
                                    const res = await requestApi<{ content: string; language: string }>("/demo/target/source?target=cipher_cloud", project, token);
                                    setCode(res.content);
                                    setLanguage("javascript");
                                  } catch {
                                    setCode(`// CipherCloud Enterprise Storage (Vulnerable: DES-CBC + MD5)\nconst crypto = require('crypto');\nfunction encryptFile(data, key, iv) {\n  const cipher = crypto.createCipheriv('des-cbc', key, iv);\n  return Buffer.concat([cipher.update(data), cipher.final()]);\n}\nfunction verifyIntegrity(data) {\n  return crypto.createHash('md5').update(data).digest('hex');\n}\n`);
                                    setLanguage("javascript");
                                  }
                                }}
                                className="rounded border border-blue-500/30 bg-blue-500/10 px-2 py-0.5 text-[10px] font-medium text-blue-300 hover:bg-blue-500/20 transition-colors"
                              >
                                ⚡ CipherCloud (DES-CBC)
                              </button>
                            </div>
                            <textarea
                              id="source-code"
                              aria-label="Source code"
                              rows={7}
                              className={`${inputClass} resize-y font-mono !text-xs leading-6`}
                              placeholder="Paste the code you want to scan…"
                              value={code}
                              onChange={(e) => setCode(e.target.value)}
                            />
                          </>
                        )}
                        <p className="text-[11px] text-quiet">
                          Up to 10,000 files or ZIP archive · up to 500 MB total. Non-source files are safely filtered.
                        </p>
                      </>
                    )}
                    {mode === "binary" && (
                      <label className="block min-w-0 rounded-md border border-dashed border-slate-600 bg-canvas/50 p-6">
                        <Upload size={24} className="mb-3 text-teal" />
                        <span className="block text-sm font-medium">
                          Choose your binary or firmware file
                        </span>
                        <span className="mt-1 block text-xs text-quiet">
                          ELF, PE, raw binary or ZIP · up to 8 MiB
                        </span>
                        <input
                          type="file"
                          aria-label="Binary file"
                          className="mt-4 block w-full min-w-0 text-xs text-quiet file:mr-3 file:rounded-md file:border-0 file:bg-surface-raised file:px-3 file:py-2 file:text-foreground"
                          onChange={(e) =>
                            setBinary(e.target.files?.[0] || null)
                          }
                        />
                        {binary && (
                          <span className="mt-3 block break-all text-xs text-teal">
                            Ready: {binary.name}
                          </span>
                        )}
                      </label>
                    )}
                    {mode === "pcap" && (
                      <div className="space-y-4">
                        <label className="block min-w-0 rounded-md border border-dashed border-slate-600 bg-canvas/50 p-6">
                          <Radio size={24} className="mb-3 text-teal" />
                          <span className="block text-sm font-medium">
                            Choose your PCAP capture file
                          </span>
                          <span className="mt-1 block text-xs text-quiet">
                            .pcap, .cap, .pcapng · up to 8 MiB
                          </span>
                          <input
                            type="file"
                            accept=".pcap,.cap,.pcapng"
                            aria-label="PCAP file"
                            className="mt-4 block w-full min-w-0 text-xs text-quiet file:mr-3 file:rounded-md file:border-0 file:bg-surface-raised file:px-3 file:py-2 file:text-foreground"
                            onChange={(e) =>
                              setPcapFile(e.target.files?.[0] || null)
                            }
                          />
                          {pcapFile && (
                            <span className="mt-3 block break-all text-xs text-teal">
                              Ready: {pcapFile.name} ({(pcapFile.size / 1024).toFixed(1)} KB)
                            </span>
                          )}
                        </label>

                        <div className="rounded-md border border-subtle bg-canvas/50 p-4 text-xs space-y-2">
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-foreground">
                              {pcapFile ? "File capture mode active" : "Or run synthetic PQC network capture"}
                            </span>
                            <label className="flex items-center gap-2 cursor-pointer">
                              <input
                                type="checkbox"
                                checked={pcapPqcHybrid}
                                onChange={(e) => setPcapPqcHybrid(e.target.checked)}
                                className="rounded border-subtle bg-canvas text-cyan-400"
                              />
                              <span className="text-[11px] text-quiet">Include FIPS 203 ML-KEM hybrid key exchange</span>
                            </label>
                          </div>
                          <p className="text-[11px] text-quiet">
                            {pcapFile
                              ? "Will extract ClientHello, ServerHello, and JA3/JA4 fingerprints from your uploaded packet capture."
                              : "No capture hardware needed. ECDAT generates realistic TLS 1.3 traffic to test passive hybrid discovery and JA4 fingerprinting."}
                          </p>
                        </div>
                      </div>
                    )}

                    <div className="flex flex-wrap items-center justify-between gap-3 border-t border-subtle pt-4">
                      <p className="text-[11px] text-quiet">
                        Results appear below when ready.
                      </p>
                      <button
                        className={buttonClass}
                        disabled={busy || !connected}
                        onClick={() => void submit()}
                      >
                        {busy ? (
                          <LoaderCircle
                            size={14}
                            className="motion-safe:animate-spin"
                          />
                        ) : (
                          <Search size={14} />
                        )}
                        {busy ? "Submitting…" : "Start scan"}
                      </button>
                    </div>
                  </div>
                </section>
                <aside className={`${panelClass} p-5`}>
                  <h3 className="flex items-center gap-2 text-xs font-semibold">
                    <CircleHelp size={15} className="text-teal" />
                    What this scan checks
                  </h3>
                  <ul className="mt-4 space-y-3">
                    {activeType.checks.map((check) => (
                      <li
                        key={check}
                        className="flex gap-2 text-xs leading-relaxed text-quiet"
                      >
                        <CheckCircle2
                          size={13}
                          className="mt-0.5 shrink-0 text-teal/70"
                        />
                        {check}
                      </li>
                    ))}
                  </ul>
                  <div className="mt-5 border-t border-subtle pt-4 text-[11px] leading-relaxed text-quiet">
                    {mode === "network"
                      ? "Only scan targets you are authorized to test. Post-quantum key exchange is tested with explicit hybrid groups; individual results show runtime and connection limitations."
                      : mode === "code"
                        ? "Python uses code structure analysis. Other languages use pattern matching, so findings may need a closer look."
                        : "A matching signature does not prove the algorithm is used. ZIP scanning covers one level, up to 100 entries and 8 MiB expanded."}
                  </div>
                </aside>
              </div>

              {/* Feature-Specific Scan History: Shows ONLY this feature's scans and findings */}
              <FeatureScanHistory
                mode={mode}
                scans={scans}
                selectedId={selected}
                onSelectScan={(id) => setSelected(id)}
                exportIds={exportIds}
                onToggleExport={(id) => {
                  setExportIds((ids) =>
                    ids.includes(id)
                      ? ids.filter((x) => x !== id)
                      : [...ids, id],
                  );
                }}
                onRescanTarget={(newTarget) => {
                  if (mode === "network") {
                    setTarget(newTarget);
                    window.scrollTo({ top: 0, behavior: "smooth" });
                  }
                }}
                onDownloadSingleCbom={(scan) => void downloadSingle(scan)}
                onRefresh={() => void refresh()}
              />
            </>
          )}
          {view === "history" && (
            <section
              className="space-y-5"
              aria-labelledby="history-page-heading"
            >
              <div className="flex flex-wrap items-end justify-between gap-4">
                <div>
                  <p className="mb-1.5 text-[10px] uppercase tracking-[0.18em] text-teal">
                    {project} / reporting
                  </p>
                  <h2
                    id="history-page-heading"
                    className="text-xl font-semibold tracking-tight sm:text-2xl"
                  >
                    History & reports
                  </h2>
                  <p className="mt-2 max-w-2xl text-sm text-quiet">
                    A consolidated record of every network, source code, and
                    firmware scan in this project. Filter the record without
                    mixing feature-specific scan workspaces.
                  </p>
                </div>
                <button
                  className="flex items-center gap-2 rounded-md border border-subtle px-3 py-2 text-xs text-quiet hover:bg-surface-raised hover:text-teal"
                  onClick={() => void refresh()}
                >
                  <RefreshCw size={14} /> Refresh records
                </button>
              </div>
              {error && (
                <div role="alert" className="ec-alert">
                  <AlertTriangle size={16} />
                  {error}
                </div>
              )}
              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                {(["network", "code", "binary"] as const).map(
                  (kind) => {
                    const Icon = scanTypes.find(
                      (type) => type.id === kind,
                    )!.icon;
                    return (
                      <button
                        key={kind}
                        onClick={() =>
                          setHistoryFilter(
                            historyFilter === kind ? "all" : kind,
                          )
                        }
                        className={`${panelClass} p-4 text-left transition-colors ${historyFilter === kind ? "border-cyan-500/40 bg-cyan-500/5" : "hover:bg-surface-raised"}`}
                      >
                        <div className="flex items-center justify-between text-quiet">
                          <span className="text-[11px]">
                            {kindLabels[kind]}
                          </span>
                          <Icon size={15} className="text-teal" />
                        </div>
                        <p className="mt-2 font-mono text-2xl font-semibold">
                          {scans.filter((scan) => scan.kind === kind).length}
                        </p>
                        <p className="mt-1 text-[10px] text-quiet">
                          {kind === "binary"
                            ? "Firmware records"
                            : "Saved scan records"}
                        </p>
                      </button>
                    );
                  },
                )}
                <div className={`${panelClass} p-4`}>
                  <p className="text-[11px] text-quiet">Selected for report</p>
                  <p className="mt-2 font-mono text-2xl font-semibold">
                    {exportIds.length}
                  </p>
                  <p className="mt-1 text-[10px] text-quiet">
                    Across all scan types
                  </p>
                </div>
              </div>
              <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
                <section
                  className={panelClass}
                  aria-labelledby="all-history-heading"
                >
                  <div className="flex flex-wrap items-center justify-between gap-3 border-b border-subtle px-5 py-3.5">
                    <h3
                      id="all-history-heading"
                      className="flex items-center gap-2 text-sm font-semibold"
                    >
                      <History size={15} className="text-teal" />
                      All scan records
                    </h3>
                    <div className="flex gap-1">
                      {(["all", "network", "code", "binary"] as const).map(
                        (filter) => (
                          <button
                            key={filter}
                            onClick={() => setHistoryFilter(filter)}
                            className={`rounded px-2 py-1 text-[10px] capitalize ${historyFilter === filter ? "bg-cyan-500/10 text-teal" : "text-quiet hover:bg-surface-raised"}`}
                          >
                            {filter === "code"
                              ? "Source code"
                              : filter === "binary"
                                ? "Firmware"
                                : filter}
                          </button>
                        ),
                      )}
                    </div>
                  </div>
                  <p className="border-b border-subtle px-5 py-3 text-[11px] text-quiet">
                    Select completed records for one consolidated CycloneDX
                    report. {historyScans.length} record
                    {historyScans.length === 1 ? "" : "s"} shown.
                  </p>
                  {!historyScans.length ? (
                    <div className="px-5 py-12 text-center">
                      <History size={25} className="mx-auto text-quiet" />
                      <p className="mt-3 text-sm">No matching records</p>
                      <p className="mt-1 text-xs text-quiet">
                        Run a scan in the corresponding feature to add it here.
                      </p>
                    </div>
                  ) : (
                    <div className="max-h-[540px] divide-y divide-[var(--ecdat-border-subtle)] overflow-auto">
                      {historyScans.map((scan) => (
                        <div
                          key={scan.id}
                          className={`border-l-2 px-4 py-3 ${selected === scan.id ? "border-l-cyan-500 bg-cyan-500/5" : "border-l-transparent hover:bg-surface-raised/30"}`}
                        >
                          <div className="flex items-center gap-3">
                            <input
                              type="checkbox"
                              className="h-3.5 w-3.5 shrink-0 accent-cyan-500"
                              aria-label={`Export scan ${scan.id}`}
                              disabled={scan.status !== "completed"}
                              checked={exportIds.includes(scan.id)}
                              onChange={(e) =>
                                setExportIds((ids) =>
                                  e.target.checked
                                    ? [...ids, scan.id]
                                    : ids.filter((id) => id !== scan.id),
                                )
                              }
                            />
                            <button
                              onClick={() => setSelected(scan.id)}
                              className="min-w-0 flex-1 text-left"
                            >
                              <span className="block truncate text-xs font-medium">
                                {scanLabel(scan)}
                              </span>
                              <span className="mt-1 block text-[10px] text-quiet">
                                {kindLabels[scan.kind]} ·{" "}
                                {new Date(scan.created_at).toLocaleString()}
                              </span>
                            </button>
                            <StatusBadge status={scan.status} />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  <div className="flex flex-wrap items-center justify-between gap-3 border-t border-subtle bg-canvas/30 p-4">
                    <div>
                      <p className="text-xs font-medium">
                        Download consolidated report
                      </p>
                      <p className="mt-1 text-[11px] text-quiet">
                        {exportIds.length
                          ? `${exportIds.length} completed scan${exportIds.length === 1 ? "" : "s"} selected`
                          : "Select completed records above"}
                      </p>
                    </div>
                    <button
                      className={`${buttonClass} !text-xs`}
                      disabled={!exportIds.length}
                      onClick={() => void download()}
                    >
                      <Download size={14} />
                      Download CBOM
                    </button>
                  </div>
                </section>
                <section
                  className={panelClass}
                  aria-labelledby="record-details-heading"
                >
                  <div className="flex items-center justify-between border-b border-subtle px-5 py-3.5">
                    <h3
                      id="record-details-heading"
                      className="flex items-center gap-2 text-sm font-semibold"
                    >
                      <FileCode2 size={15} className="text-teal" />
                      Record details
                    </h3>
                    {historyCurrent && (
                      <StatusBadge status={historyCurrent.status} />
                    )}
                  </div>
                  {!historyCurrent ? (
                    <div className="px-5 py-16 text-center">
                      <Search size={28} className="mx-auto text-quiet" />
                      <p className="mt-3 text-sm">
                        Select a record to review its results
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-4 p-5">
                      <div>
                        <p className="break-all text-sm font-medium">
                          {scanLabel(historyCurrent)}
                        </p>
                        <p className="mt-1 text-[11px] text-quiet">
                          {kindLabels[historyCurrent.kind]} ·{" "}
                          {new Date(historyCurrent.created_at).toLocaleString()}
                        </p>
                      </div>
                      {historyCurrent.error && (
                        <div
                          role="alert"
                          className="rounded-md border border-red-500/20 bg-red-500/5 p-3 text-xs text-danger"
                        >
                          {historyCurrent.error}
                        </div>
                      )}
                      {historyCurrent.result ? (
                        <>
                          <div className="grid grid-cols-2 gap-2">
                            <div className="rounded-md border border-subtle bg-canvas/50 p-3">
                              <p className="text-[10px] text-quiet">Findings</p>
                              <p className="mt-1 text-lg font-semibold">
                                {
                                  (
                                    historyCurrent.result.findings ||
                                    historyCurrent.result.detections ||
                                    []
                                  ).length
                                }
                              </p>
                            </div>
                            <div className="rounded-md border border-subtle bg-canvas/50 p-3">
                              <p className="text-[10px] text-quiet">
                                Scan type
                              </p>
                              <p className="mt-1 text-sm font-medium">
                                {kindLabels[historyCurrent.kind]}
                              </p>
                            </div>
                          </div>
                          {historyCurrent.kind === "network" && (
                            <>
                              <div className="rounded-md border border-subtle bg-canvas/50 p-3 text-xs">
                                <p>
                                  TLS:{" "}
                                  {historyCurrent.result.protocol ||
                                    "Not measured"}
                                </p>
                                <p className="mt-1">
                                  Encryption:{" "}
                                  {historyCurrent.result.cipher_name ||
                                    "Not measured"}
                                </p>
                              </div>
                              <div
                                className={`rounded-md border p-3 text-xs ${historyCurrent.result.quantum_vulnerable === true ? "border-red-500/25 bg-red-500/5 text-danger" : historyCurrent.result.quantum_vulnerable === false ? "border-emerald-500/25 bg-emerald-500/5 text-success" : "border-amber-500/25 bg-amber-500/5 text-warning"}`}
                              >
                                <p className="font-semibold">
                                  Post-quantum threat assessment
                                </p>
                                <p className="mt-1">
                                  {historyCurrent.result.quantum_vulnerable ===
                                  true
                                    ? "Potentially vulnerable to a post-quantum threat. Prioritize cryptographic migration."
                                    : historyCurrent.result
                                          .quantum_vulnerable === false
                                      ? "No post-quantum vulnerability was identified by this scan."
                                      : "Not conclusive. The scanner could not determine post-quantum exposure."}
                                </p>
                                <p className="mt-2 text-quiet">
                                  PQC capability:{" "}
                                  {historyCurrent.result.pqc_status ||
                                    "Not measured"}
                                </p>
                                {historyCurrent.result.hndl_risk && (
                                  <p className="mt-1 text-quiet">
                                    Harvest-now, decrypt-later risk:{" "}
                                    {historyCurrent.result.hndl_risk}
                                  </p>
                                )}
                                {historyCurrent.result.hndl_rationale && (
                                  <p className="mt-1 leading-relaxed text-quiet">
                                    {historyCurrent.result.hndl_rationale}
                                  </p>
                                )}
                              </div>
                            </>
                          )}
                          {historyCurrent.kind !== "network" && (
                            <div className="rounded-md border border-amber-500/25 bg-amber-500/5 p-3 text-xs text-warning">
                              <p className="font-semibold">
                                Post-quantum threat assessment
                              </p>
                              <p className="mt-1">
                                This scan type identifies cryptographic evidence
                                but does not determine whether the deployed
                                system is post-quantum vulnerable. Review its
                                findings and run a network scan for measured TLS
                                exposure.
                              </p>
                            </div>
                          )}
                          <details
                            className="rounded-md border border-subtle"
                            open={historyCurrent.kind === "binary"}
                          >
                            <summary className="cursor-pointer px-3 py-3 text-xs font-medium">
                              Complete{" "}
                              {historyCurrent.kind === "binary"
                                ? "firmware"
                                : "scan"}{" "}
                              details & evidence
                            </summary>
                            <pre className="max-h-[420px] overflow-auto border-t border-subtle bg-canvas/50 p-3 text-[10px] leading-relaxed whitespace-pre-wrap break-all text-quiet">
                              {JSON.stringify(
                                {
                                  scan_id: historyCurrent.id,
                                  kind: historyCurrent.kind,
                                  status: historyCurrent.status,
                                  created_at: historyCurrent.created_at,
                                  engine_version: historyCurrent.engine_version,
                                  input_hash: historyCurrent.input_hash,
                                  error: historyCurrent.error,
                                  result: historyCurrent.result,
                                },
                                null,
                                2,
                              )}
                            </pre>
                          </details>
                        </>
                      ) : (
                        <p className="rounded-md bg-surface-raised p-3 text-xs text-quiet">
                          This scan has not produced a result yet.
                        </p>
                      )}
                    </div>
                  )}
                </section>
              </div>
            </section>
          )}
          <footer className="flex flex-wrap items-center justify-between gap-2 border-t border-subtle pt-4 text-[10px] text-quiet">
            <span className="flex items-center gap-1.5">
              <ShieldCheck size={12} />
              ECDAT · Cryptographic discovery
            </span>
            <span>Saved scans · Measured evidence · CycloneDX reports</span>
          </footer>
        </div>
      </main>
    </div>
  );
}
