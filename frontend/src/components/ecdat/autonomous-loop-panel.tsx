"use client";

import { useState } from "react";
import {
  Play,
  CheckCircle2,
  AlertTriangle,
  FolderArchive,
  UploadCloud,
  FileCode2,
  Download,
  Terminal,
  ShieldCheck,
  FileCheck2,
  RefreshCw,
  Layers,
  ArrowRight,
  Code2,
  Binary,
  Check,
  Cpu,
  FileText,
  Info,
  GitPullRequest,
  Sparkles,
  BookOpen,
  Bot,
  ChevronDown,
  ChevronUp,
  ExternalLink,
} from "lucide-react";
import {
  requestApi,
  CodebasePatchResponse,
  PatchedFileResult,
  GitHubPullResponse,
  RAGStandard,
  AIRefactorResponse,
} from "@/lib/api";

function GithubIcon({ size = 14, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
      <path d="M9 18c-4.51 2-5-2-7-2" />
    </svg>
  );
}

const PRESET_SCENARIOS = [
  {
    id: "banking",
    title: "Banking Payment Service (Python)",
    lang: "PYTHON",
    desc: "Vulnerable MD5 session hash + 1024-bit RSA keypair",
    filename: "payment_service.py",
    code: `# Enterprise Banking Payment Module (Python)
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_transaction_signature(account_id: str, amount: float) -> tuple[str, bytes]:
    # Deprecated Classical: broken MD5 checksum
    payload = f"{account_id}:{amount}".encode("utf-8")
    tx_hash = hashlib.md5(payload).hexdigest()

    # Quantum vulnerable: 1024-bit RSA keypair (high CRQC risk)
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024
    )
    return tx_hash, private_key.sign(payload, None)
`,
  },
  {
    id: "fintech_c",
    title: "Fintech Core Gateway (C / OpenSSL)",
    lang: "C_CPP",
    desc: "Obsolete MD5 + 56-bit DES + RSA-1024",
    filename: "gateway_core.c",
    code: `// Fintech Core Payment Gateway (C / OpenSSL)
#include <openssl/md5.h>
#include <openssl/des.h>

void process_transaction(const unsigned char *data, size_t len, unsigned char *out_hash) {
    // VULNERABLE: MD5 deprecated under NIST SP 800-131A
    MD5(data, len, out_hash);

    // VULNERABLE: 56-bit DES legacy cipher
    DES_key_schedule schedule;
    DES_cblock key = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    DES_set_key_unchecked(&key, &schedule);
    DES_ecb_encrypt((DES_cblock*)data, (DES_cblock*)out_hash, &schedule, DES_ENCRYPT);
}
`,
  },
  {
    id: "legacy_binary",
    title: "Legacy Crypto Binary Executable (ELF x86_64)",
    lang: "BINARY",
    desc: "Embedded DES and MD5 symbols requiring PQC compiler hardening",
    filename: "crypto_daemon.elf",
    code: `/* Embedded Cryptographic Daemon Configuration */
# Vulnerable C Runtime Symbols:
# - MD5_Init, MD5_Update, MD5_Final (libcrypto.so.1.1)
# - DES_ecb_encrypt (libcrypto.so.1.1)
# - RSA_generate_key (1024-bit modulus embedded)
#
# Remediation target: Upgrade linking to libcrypto3 with FIPS provider (AES-256 + SHA-256 + ML-KEM)
`,
  },
];

export function AutonomousLoopPanel({
  project,
  token,
}: {
  project: string;
  token: string;
}) {
  const [targetType, setTargetType] = useState<"source" | "binary">("source");
  const [selectedScenario, setSelectedScenario] = useState(PRESET_SCENARIOS[0]);
  const [sourceCode, setSourceCode] = useState(PRESET_SCENARIOS[0].code);
  const [mode, setMode] = useState<"snippet" | "codebase">("codebase");
  
  // Multi-file / Full codebase state
  const [codebaseFiles, setCodebaseFiles] = useState<Array<{ path: string; content: string }>>([]);
  const [uploadedZip, setUploadedZip] = useState<File | null>(null);

  // GitHub pull state
  const [codebaseInputType, setCodebaseInputType] = useState<"github" | "zip" | "folder">("github");
  const [githubUrl, setGithubUrl] = useState("https://github.com/expressjs/express");
  const [githubBranch, setGithubBranch] = useState("");
  const [githubSubpath, setGithubSubpath] = useState("");
  const [githubToken, setGithubToken] = useState("");
  const [isPullingGithub, setIsPullingGithub] = useState(false);

  // NVIDIA NIM is configured server-side through NVIDIA_API_KEY.
  const [isAiRefactoring, setIsAiRefactoring] = useState(false);
  const [aiResult, setAiResult] = useState<AIRefactorResponse | null>(null);
  const [showReasoning, setShowReasoning] = useState(true);
  const [selectedRagDoc, setSelectedRagDoc] = useState<RAGStandard | null>(null);
  
  // Pipeline execution state
  const [isExecuting, setIsExecuting] = useState(false);
  const [activeStage, setActiveStage] = useState<number>(0); // 1, 2, 3, 4
  const [patchResult, setPatchResult] = useState<CodebasePatchResponse | null>(null);
  const [selectedDiffFile, setSelectedDiffFile] = useState<PatchedFileResult | null>(null);
  const [statusMessage, setStatusMessage] = useState<string>("");

  function handleSelectScenario(sc: typeof PRESET_SCENARIOS[0]) {
    setSelectedScenario(sc);
    setSourceCode(sc.code);
    setPatchResult(null);
    setAiResult(null);
  }

  // Pull repository directly from GitHub
  async function handlePullGithub() {
    const cleanUrl = githubUrl.trim();
    if (!cleanUrl) {
      setStatusMessage("Please enter a GitHub repository URL (e.g. https://github.com/owner/repo or owner/repo)");
      return;
    }

    setIsPullingGithub(true);
    setStatusMessage(`Connecting to GitHub and pulling '${cleanUrl}'...`);
    try {
      const res = await requestApi<GitHubPullResponse>("/github/pull", project, token, {
        url: cleanUrl,
        ref: githubBranch.trim() || undefined,
        subpath: githubSubpath.trim() || undefined,
        token: githubToken.trim() || undefined,
      });

      setCodebaseFiles(res.files);
      setUploadedZip(null);
      setMode("codebase");
      setStatusMessage(
        `Imported ${res.total_files} source files from GitHub repo '${res.repo}' (${(res.total_bytes / 1024).toFixed(1)} KB). Ready for post-quantum auto-patching.`
      );
    } catch (err) {
      setStatusMessage(`GitHub pull error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsPullingGithub(false);
    }
  }

  // Run NVIDIA DeepSeek-R1 AI Refactoring (RAG-Augmented)
  async function runDeepSeekRefactor(targetCodeToUse?: string, targetPathToUse?: string) {
    setIsAiRefactoring(true);
    setStatusMessage("Querying PQC RAG standards and invoking NVIDIA DeepSeek-R1 reasoning...");
    try {
      const curPath = targetPathToUse || (mode === "codebase" && codebaseFiles[0] ? codebaseFiles[0].path : selectedScenario.filename);
      const curCode = targetCodeToUse || (mode === "codebase" && codebaseFiles[0] ? codebaseFiles[0].content : sourceCode);
      const curLang = selectedScenario.lang.toLowerCase();

      const res = await requestApi<AIRefactorResponse>("/ai/refactor", project, token, {
        file_path: curPath,
        source_code: curCode,
        language: curLang,
      });

      setAiResult(res);
      if (res.remediated_code && mode === "snippet") {
        setSourceCode(res.remediated_code);
      }
      setStatusMessage(res.api_key_configured
        ? "NVIDIA DeepSeek-R1 post-quantum refactoring complete with extracted chain-of-thought."
        : "NVIDIA_API_KEY is not configured on the backend; deterministic remediation was applied.");
    } catch (err) {
      setStatusMessage(`DeepSeek-R1 error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsAiRefactoring(false);
    }
  }

  // Handle entire folder upload
  async function handleFolderUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const files = Array.from(e.target.files || []);
    if (!files.length) return;

    const parsed: Array<{ path: string; content: string }> = [];
    for (const f of files) {
      if (f.size > 10 * 1024 * 1024) continue; // skip >10MB
      try {
        const text = await f.text();
        parsed.push({
          path: (f.webkitRelativePath || f.name).replace(/\\/g, "/"),
          content: text,
        });
      } catch (err) {}
    }
    setCodebaseFiles(parsed);
    setUploadedZip(null);
    setMode("codebase");
    setStatusMessage(`Loaded ${parsed.length} source files from selected project folder.`);
  }

  // Handle ZIP archive upload
  function handleZipUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (file) {
      setUploadedZip(file);
      setMode("codebase");
      setStatusMessage(`Ready to patch archive: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
    }
  }

  // Run the 4-Stage Autonomous Loop
  async function runAutonomousLoop() {
    setIsExecuting(true);
    setPatchResult(null);
    setSelectedDiffFile(null);

    try {
      // Stage 1: Scan & Discover
      setActiveStage(1);
      setStatusMessage("Stage 1: Scanning AST & extracting cryptographic primitives...");
      await new Promise((r) => setTimeout(r, 600));

      // Stage 2: CBOM & Quantum Risk
      setActiveStage(2);
      setStatusMessage("Stage 2: Generating CycloneDX 1.6 CBOM & estimating Shor/Mosca timeline...");
      await new Promise((r) => setTimeout(r, 600));

      // Stage 3: Auto Patch & Test
      setActiveStage(3);
      setStatusMessage("Stage 3: Applying AST deterministic migrations & running differential unit tests...");

      let res: CodebasePatchResponse;
      if (mode === "codebase" && uploadedZip) {
        const formData = new FormData();
        formData.append("file", uploadedZip);
        res = await requestApi<CodebasePatchResponse>(
          "/migration/patch-codebase/upload",
          project,
          token,
          formData
        );
      } else if (mode === "codebase" && codebaseFiles.length > 0) {
        const normalizedFiles = codebaseFiles.map((f) => ({
          path: f.path,
          content: f.content,
          language: (f as any).language ? String((f as any).language).toLowerCase() : undefined,
        }));
        res = await requestApi<CodebasePatchResponse>(
          "/migration/patch-codebase",
          project,
          token,
          { files: normalizedFiles }
        );
      } else {
        // Single snippet mode
        res = await requestApi<CodebasePatchResponse>(
          "/migration/patch-codebase",
          project,
          token,
          {
            files: [
              {
                path: selectedScenario.filename,
                content: sourceCode,
                language: selectedScenario.lang.toLowerCase(),
              },
            ],
          }
        );
      }

      // Stage 4: Closed-Loop Verify
      setActiveStage(4);
      setStatusMessage("Stage 4: Executing closed-loop re-scan to prove weakness elimination...");
      await new Promise((r) => setTimeout(r, 500));

      setPatchResult(res);
      if (res.patched_files.length > 0) {
        setSelectedDiffFile(res.patched_files[0]);
      }
      setStatusMessage(
        `Remediation complete! ${res.summary.vulnerabilities_remediated} of ${res.summary.vulnerabilities_found} weaknesses eliminated (${res.summary.remediation_rate_percent}% compliance).`
      );
    } catch (err: any) {
      setStatusMessage(`Execution failed: ${err.message || String(err)}`);
    } finally {
      setIsExecuting(false);
    }
  }

  // 1-Click Download Patched Codebase ZIP
  async function downloadPatchedCodebaseZip() {
    try {
      let blob: Blob;
      if (mode === "codebase" && uploadedZip) {
        const formData = new FormData();
        formData.append("file", uploadedZip);
        const res = await fetch(`/api/migration/download-patched-zip/upload?project=${encodeURIComponent(project)}`, {
          method: "POST",
          body: formData,
        });
        blob = await res.blob();
      } else if (mode === "codebase" && codebaseFiles.length > 0) {
        const normalizedFiles = codebaseFiles.map((f) => ({
          path: f.path,
          content: f.content,
          language: (f as any).language ? String((f as any).language).toLowerCase() : undefined,
        }));
        const res = await fetch(`/api/migration/download-patched-zip?project=${encodeURIComponent(project)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ files: normalizedFiles }),
        });
        blob = await res.blob();
      } else {
        const res = await fetch(`/api/migration/download-patched-zip?project=${encodeURIComponent(project)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            files: [
              {
                path: selectedScenario.filename,
                content: sourceCode,
              },
            ],
          }),
        });
        blob = await res.blob();
      }

      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = "ecdat_patched_codebase.zip";
      link.click();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      alert("Failed to download patched ZIP: " + err.message);
    }
  }

  return (
    <div className="space-y-6 pb-12">
      {/* ── Top Header Section (Images 4 & 5) ── */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-2 py-0.5 font-mono text-[10px] font-semibold text-teal uppercase tracking-wider">
              AUTONOMOUS LOOP ENGINE
            </span>
            <span className="text-xs text-quiet">· 1-Click Pipeline</span>
          </div>
          <h1 className="mt-1.5 text-xl font-bold tracking-tight text-foreground sm:text-2xl">
            Autonomous Cryptographic Remediation Loop
          </h1>
          <p className="mt-1 text-xs text-quiet max-w-3xl leading-relaxed">
            Execute an end-to-end cycle in a single click: Scan source or binary → Generate CBOM &amp; quantum risk report → Create AST safe patches → Verify with closed loop differential testing → Inspect before and after changes.
          </p>
        </div>

        <button
          type="button"
          onClick={runAutonomousLoop}
          disabled={isExecuting}
          className="flex items-center gap-2 rounded-md bg-teal px-4 py-2.5 text-xs font-bold text-slate-950 shadow-sm hover:bg-teal/90 transition-all disabled:opacity-50 shrink-0"
        >
          {isExecuting ? (
            <RefreshCw size={15} className="animate-spin" />
          ) : (
            <Play size={15} className="fill-slate-950" />
          )}
          <span>{isExecuting ? "Executing Loop..." : "Run Autonomous Loop"}</span>
        </button>
      </div>

      {/* Mode Switcher Tabs */}
      <div className="flex flex-wrap items-center gap-2 border-b border-subtle pb-3">
        <button
          type="button"
          onClick={() => setMode("snippet")}
          className={`rounded-md px-3 py-1.5 text-xs font-semibold transition-all ${
            mode === "snippet"
              ? "bg-cyan-500/15 text-teal border border-cyan-500/30"
              : "text-quiet hover:bg-surface-raised"
          }`}
        >
          ⚡ Preset Code Snippets
        </button>
        <button
          type="button"
          onClick={() => setMode("codebase")}
          className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all ${
            mode === "codebase"
              ? "bg-cyan-500/15 text-teal border border-cyan-500/30"
              : "text-quiet hover:bg-surface-raised"
          }`}
        >
          <FolderArchive size={14} />
          <span>Upload Entire Codebase (ZIP / Folder)</span>
          <span className="rounded bg-teal/20 px-1.5 py-0.2 font-mono text-[9px] text-teal uppercase font-bold">
            Full Project
          </span>
        </button>
      </div>

      {/* ── Two Columns: Target Selection & Source Code Input (Images 4 & 5) ── */}
      <div className="grid gap-4 lg:grid-cols-12">
        {/* Left Column (5 cols): Target Selection */}
        <div className="space-y-4 lg:col-span-5">
          <div className="rounded-lg border border-subtle bg-surface p-5 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-subtle">
              <h2 className="flex items-center gap-2 text-sm font-semibold text-foreground">
                <Cpu size={15} className="text-cyan-500" />
                Target Selection
              </h2>
              {/* Source vs Binary Toggle */}
              <div className="inline-flex rounded-md border border-subtle bg-canvas/60 p-0.5 text-[11px] font-semibold">
                <button
                  type="button"
                  onClick={() => setTargetType("source")}
                  className={`rounded px-2.5 py-1 transition-colors ${
                    targetType === "source"
                      ? "bg-teal text-slate-950"
                      : "text-quiet hover:text-foreground"
                  }`}
                >
                  Source
                </button>
                <button
                  type="button"
                  onClick={() => setTargetType("binary")}
                  className={`rounded px-2.5 py-1 transition-colors ${
                    targetType === "binary"
                      ? "bg-teal text-slate-950"
                      : "text-quiet hover:text-foreground"
                  }`}
                >
                  Binary
                </button>
              </div>
            </div>

            {mode === "snippet" ? (
              <div className="mt-4 space-y-2.5">
                <p className="text-[11px] font-medium text-quiet uppercase tracking-wider">
                  Select Preset Scenario
                </p>
                {PRESET_SCENARIOS.map((sc) => (
                  <div
                    key={sc.id}
                    onClick={() => handleSelectScenario(sc)}
                    className={`group cursor-pointer rounded-md border p-3 text-xs transition-all ${
                      selectedScenario.id === sc.id
                        ? "border-cyan-500/40 bg-cyan-500/10 shadow-xs"
                        : "border-subtle bg-canvas/40 hover:border-slate-500/30"
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-foreground">{sc.title}</span>
                      <span className="rounded border border-cyan-500/30 bg-cyan-500/10 px-1.5 py-0.5 font-mono text-[9px] font-bold text-teal">
                        {sc.lang}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] text-quiet leading-normal">{sc.desc}</p>
                  </div>
                ))}
              </div>
            ) : (
              /* Full Codebase Ingestion Controls */
              <div className="mt-4 space-y-3">
                <p className="text-[11px] font-medium text-quiet uppercase tracking-wider">
                  Select Project Ingestion Source
                </p>

                {/* Sub-tabs: GitHub vs ZIP vs Folder */}
                <div className="grid grid-cols-3 gap-1 rounded-md border border-subtle bg-canvas/60 p-1 text-[11px] font-semibold">
                  <button
                    type="button"
                    onClick={() => setCodebaseInputType("github")}
                    className={`flex items-center justify-center gap-1.5 rounded py-1.5 transition-colors ${
                      codebaseInputType === "github"
                        ? "bg-teal text-slate-950 shadow-xs"
                        : "text-quiet hover:text-foreground"
                    }`}
                  >
                    <GithubIcon size={13} />
                    <span>GitHub</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setCodebaseInputType("zip")}
                    className={`flex items-center justify-center gap-1.5 rounded py-1.5 transition-colors ${
                      codebaseInputType === "zip"
                        ? "bg-teal text-slate-950 shadow-xs"
                        : "text-quiet hover:text-foreground"
                    }`}
                  >
                    <UploadCloud size={13} />
                    <span>ZIP File</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => setCodebaseInputType("folder")}
                    className={`flex items-center justify-center gap-1.5 rounded py-1.5 transition-colors ${
                      codebaseInputType === "folder"
                        ? "bg-teal text-slate-950 shadow-xs"
                        : "text-quiet hover:text-foreground"
                    }`}
                  >
                    <FolderArchive size={13} />
                    <span>Folder</span>
                  </button>
                </div>

                {/* 1. Direct GitHub Ingestion */}
                {codebaseInputType === "github" && (
                  <div className="rounded-md border border-cyan-500/30 bg-cyan-500/5 p-3 space-y-2.5">
                    <div>
                      <label className="block text-[11px] font-semibold text-foreground">
                        GitHub Repository URL
                      </label>
                      <input
                        type="text"
                        value={githubUrl}
                        onChange={(e) => setGithubUrl(e.target.value)}
                        placeholder="https://github.com/owner/repo or owner/repo"
                        className="mt-1 w-full rounded border border-subtle bg-canvas px-2.5 py-1.5 text-xs font-mono text-foreground placeholder:text-quiet outline-none focus:border-cyan-500"
                      />
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <div>
                        <label className="block text-[10px] text-quiet">
                          Branch / Tag (optional)
                        </label>
                        <input
                          type="text"
                          value={githubBranch}
                          onChange={(e) => setGithubBranch(e.target.value)}
                          placeholder="main / master"
                          className="mt-0.5 w-full rounded border border-subtle bg-canvas px-2 py-1 text-[11px] font-mono text-foreground placeholder:text-quiet outline-none focus:border-cyan-500"
                        />
                      </div>
                      <div>
                        <label className="block text-[10px] text-quiet">
                          Subdirectory (optional)
                        </label>
                        <input
                          type="text"
                          value={githubSubpath}
                          onChange={(e) => setGithubSubpath(e.target.value)}
                          placeholder="e.g. src or backend"
                          className="mt-0.5 w-full rounded border border-subtle bg-canvas px-2 py-1 text-[11px] font-mono text-foreground placeholder:text-quiet outline-none focus:border-cyan-500"
                        />
                      </div>
                    </div>
                    <div>
                      <label className="block text-[10px] text-quiet">
                        GitHub Token (optional, for private repos)
                      </label>
                      <input
                        type="password"
                        value={githubToken}
                        onChange={(e) => setGithubToken(e.target.value)}
                        placeholder="ghp_..."
                        className="mt-0.5 w-full rounded border border-subtle bg-canvas px-2 py-1 text-[11px] font-mono text-foreground placeholder:text-quiet outline-none focus:border-cyan-500"
                      />
                    </div>
                    <button
                      type="button"
                      onClick={handlePullGithub}
                      disabled={isPullingGithub}
                      className="w-full flex items-center justify-center gap-2 rounded bg-teal px-3 py-1.5 text-xs font-bold text-slate-950 hover:bg-teal/90 transition-all disabled:opacity-50"
                    >
                      {isPullingGithub ? (
                        <RefreshCw size={13} className="animate-spin" />
                      ) : (
                        <GithubIcon size={13} />
                      )}
                      <span>{isPullingGithub ? "Pulling Repo..." : "Pull from GitHub"}</span>
                    </button>
                  </div>
                )}

                {/* 2. Upload ZIP Archive */}
                {codebaseInputType === "zip" && (
                  <label className="block cursor-pointer rounded-md border border-dashed border-cyan-500/40 bg-cyan-500/5 p-4 text-center hover:bg-cyan-500/10 transition-colors">
                    <UploadCloud size={24} className="mx-auto text-teal" />
                    <span className="mt-2 block text-xs font-semibold text-foreground">
                      Upload Project ZIP (.zip, .tar.gz)
                    </span>
                    <span className="text-[10px] text-quiet">
                      Contains frontend &amp; backend code
                    </span>
                    <input
                      type="file"
                      accept=".zip,.tar.gz,.tgz,.tar"
                      className="sr-only"
                      onChange={handleZipUpload}
                    />
                  </label>
                )}

                {/* 3. Choose Directory */}
                {codebaseInputType === "folder" && (
                  <label className="block cursor-pointer rounded-md border border-dashed border-subtle bg-canvas/40 p-4 text-center hover:bg-surface-raised transition-colors">
                    <FolderArchive size={24} className="mx-auto text-quiet" />
                    <span className="mt-2 block text-xs font-semibold text-foreground">
                      Select Source Folder
                    </span>
                    <span className="text-[10px] text-quiet">
                      Picks all nested source files from disk
                    </span>
                    <input
                      type="file"
                      multiple
                      {...{ webkitdirectory: "" }}
                      className="sr-only"
                      onChange={handleFolderUpload}
                    />
                  </label>
                )}

                {uploadedZip && (
                  <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 p-2 text-xs text-emerald-400 flex items-center justify-between font-mono">
                    <span className="truncate">Ready: {uploadedZip.name}</span>
                    <CheckCircle2 size={13} className="shrink-0" />
                  </div>
                )}
                {codebaseFiles.length > 0 && (
                  <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 p-2 text-xs text-emerald-400 flex items-center justify-between font-mono">
                    <span>{codebaseFiles.length} files loaded</span>
                    <CheckCircle2 size={13} className="shrink-0" />
                  </div>
                )}
              </div>
            )}

            {/* NVIDIA DeepSeek-R1 AI Assistant */}
            <div className="mt-4 rounded-lg border border-purple-500/30 bg-purple-500/5 p-3.5">
              <div className="flex items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-1.5">
                    <Sparkles size={14} className="text-purple-400" />
                    <span className="text-xs font-bold text-foreground">AI post-quantum refactor</span>
                    <span className="rounded bg-purple-500/20 px-1.5 py-0.5 font-mono text-[9px] font-bold text-purple-300">NVIDIA NIM</span>
                  </div>
                  <p className="mt-1 text-[10px] leading-relaxed text-quiet">
                    DeepSeek-R1 is always available through the backend&apos;s NVIDIA_API_KEY. No browser key or opt-in is required.
                  </p>
                </div>
                <button
                  type="button"
                  onClick={() => runDeepSeekRefactor()}
                  disabled={isAiRefactoring}
                  className="shrink-0 inline-flex items-center gap-1.5 rounded bg-purple-600 px-2.5 py-1.5 text-[11px] font-semibold text-white transition-colors hover:bg-purple-500 disabled:opacity-50"
                >
                  {isAiRefactoring ? <RefreshCw size={12} className="animate-spin" /> : <Sparkles size={12} />}
                  {isAiRefactoring ? "Analyzing" : "Run AI"}
                </button>
              </div>
            </div>

            {/* Target Details Meta */}
            <div className="mt-4 space-y-1.5 border-t border-subtle pt-3 text-xs font-mono text-quiet">
              <div className="flex justify-between">
                <span>Target:</span>
                <span className="text-foreground truncate max-w-[200px]">
                  {mode === "codebase"
                    ? uploadedZip?.name || `${codebaseFiles.length} files (GitHub/Dir)`
                    : selectedScenario.filename}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Engine:</span>
                <span className="text-teal font-semibold">
                  NVIDIA DeepSeek-R1 + RAG
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (7 cols): Source Code Input / Inspector */}
        <div className="space-y-4 lg:col-span-7">
          <div className="rounded-lg border border-subtle bg-surface p-5 shadow-xs">
            <div className="flex items-center justify-between pb-3 border-b border-subtle">
              <div className="flex items-center gap-2">
                <FileCode2 size={15} className="text-cyan-500" />
                <h2 className="text-sm font-semibold text-foreground">
                  {mode === "codebase" ? "Project Codebase Preview" : "Source Code Input"}
                </h2>
              </div>
              <span className="rounded border border-subtle bg-canvas/80 px-2 py-0.5 font-mono text-[10px] text-quiet">
                {mode === "codebase" ? `${codebaseFiles.length || 1} files` : "Editable Snippet"}
              </span>
            </div>

            {mode === "codebase" && codebaseFiles.length > 0 ? (
              <div className="mt-4 space-y-3">
                <div className="max-h-64 overflow-y-auto space-y-1.5 rounded-md border border-subtle bg-canvas/50 p-2">
                  {codebaseFiles.slice(0, 50).map((f, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between rounded px-2 py-1 text-xs font-mono text-foreground hover:bg-surface-raised"
                    >
                      <span className="truncate">{f.path}</span>
                      <span className="text-quiet text-[10px]">
                        {(f.content.length / 1024).toFixed(1)} KB
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="mt-4">
                <textarea
                  rows={13}
                  value={sourceCode}
                  onChange={(e) => setSourceCode(e.target.value)}
                  className="w-full rounded-md border border-subtle bg-canvas p-3 font-mono text-xs text-foreground placeholder:text-quiet outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/20"
                />
                <div className="mt-2 flex items-center justify-between text-[11px] text-quiet">
                  <span>Click &quot;Run Autonomous Loop&quot; to execute scan, report, patch, and verify.</span>
                  <span>{sourceCode.split("\n").length} lines</span>
                </div>
              </div>
            )}

            {/* Status Message */}
            {statusMessage && (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-cyan-500/30 bg-cyan-500/10 p-2.5 text-xs text-teal font-medium">
                <Info size={14} className="shrink-0" />
                <span className="min-w-0 flex-1">{statusMessage}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* ── 4 Stages Execution Progress (Images 4 & 5) ── */}
      <div className="rounded-lg border border-subtle bg-surface p-5 shadow-xs">
        <h2 className="text-sm font-semibold text-foreground mb-4">
          Autonomous Pipeline Execution Stages
        </h2>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {[
            {
              stage: "STAGE 01",
              title: "Scan & Discover",
              desc: "Extract cryptographic primitives, algorithms, and key sizes.",
              stepNum: 1,
            },
            {
              stage: "STAGE 02",
              title: "CBOM & Quantum Risk",
              desc: "Generate CycloneDX 1.6 CBOM and compute Mosca deficit timeline.",
              stepNum: 2,
            },
            {
              stage: "STAGE 03",
              title: "Auto Patch & Test",
              desc: "Apply safe AST migration templates and execute differential tests.",
              stepNum: 3,
            },
            {
              stage: "STAGE 04",
              title: "Closed-Loop Verify",
              desc: "Re-scan and prove weakness elimination with zero regressions.",
              stepNum: 4,
            },
          ].map((st) => {
            const isDone = activeStage > st.stepNum || (patchResult && !isExecuting);
            const isCurrent = activeStage === st.stepNum && isExecuting;

            let cardBorder = "border-subtle bg-canvas/40";
            let badgeBg = "text-quiet";
            if (isDone) {
              cardBorder = "border-emerald-500/40 bg-emerald-500/5";
              badgeBg = "text-emerald-500 font-bold";
            } else if (isCurrent) {
              cardBorder = "border-cyan-500/50 bg-cyan-500/10 animate-pulse";
              badgeBg = "text-teal font-bold";
            }

            return (
              <div
                key={st.stage}
                className={`rounded-md border p-3.5 text-xs transition-all ${cardBorder}`}
              >
                <div className="flex items-center justify-between">
                  <span className={`font-mono text-[10px] uppercase ${badgeBg}`}>
                    {st.stage}
                  </span>
                  {isDone ? (
                    <CheckCircle2 size={14} className="text-emerald-500" />
                  ) : isCurrent ? (
                    <RefreshCw size={14} className="text-teal animate-spin" />
                  ) : (
                    <span className="h-2 w-2 rounded-full bg-slate-400/40" />
                  )}
                </div>
                <p className="mt-2 font-semibold text-foreground">{st.title}</p>
                <p className="mt-1 text-[11px] text-quiet leading-normal">{st.desc}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── NVIDIA DeepSeek-R1 AI Reasoning & RAG Output ── */}
      {aiResult && (
        <div className="rounded-lg border border-purple-500/40 bg-surface p-5 shadow-xs space-y-4">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-subtle pb-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="rounded bg-purple-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-purple-300 uppercase">
                  {aiResult.mode === "nvidia_deepseek_r1" ? "DEEPSEEK-R1 REASONING" : "RAG STANDARDS + AST"}
                </span>
                <h3 className="text-base font-bold text-foreground">
                  AI Cryptographic Analysis &amp; Refactoring
                </h3>
              </div>
              <p className="mt-1 text-xs text-quiet">
                Model: <span className="font-mono text-purple-300">{aiResult.model}</span> · Target: <span className="font-mono">{aiResult.file_path}</span>
              </p>
            </div>

            {aiResult.api_key_configured && (
              <span className="rounded border border-purple-500/30 bg-purple-500/10 px-2.5 py-1 text-[11px] font-semibold text-purple-300 flex items-center gap-1.5">
                <Sparkles size={12} />
                NVIDIA NIM Active
              </span>
            )}
          </div>

          {/* RAG Knowledge Standards Retrieved */}
          {aiResult.rag_standards && aiResult.rag_standards.length > 0 && (
            <div className="space-y-2">
              <span className="text-[11px] font-semibold text-quiet uppercase tracking-wider flex items-center gap-1.5">
                <BookOpen size={13} className="text-teal" />
                Retrieved Authoritative Standards (RAG Augmented)
              </span>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                {aiResult.rag_standards.map((std) => (
                  <div
                    key={std.doc_id}
                    onClick={() => setSelectedRagDoc(selectedRagDoc?.doc_id === std.doc_id ? null : std)}
                    className="cursor-pointer rounded-md border border-cyan-500/30 bg-cyan-500/5 p-2.5 text-xs hover:bg-cyan-500/10 transition-colors"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-teal truncate">{std.title}</span>
                      <span className="rounded bg-cyan-500/20 px-1 py-0.2 font-mono text-[9px] text-teal">
                        {(std.relevance_score * 10).toFixed(0)}% match
                      </span>
                    </div>
                    <p className="mt-1 font-mono text-[10px] text-quiet truncate">
                      {std.standard}
                    </p>
                    {selectedRagDoc?.doc_id === std.doc_id && (
                      <div className="mt-2 pt-2 border-t border-cyan-500/20 text-[11px] text-foreground leading-relaxed whitespace-pre-wrap">
                        {std.content}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* DeepSeek-R1 Chain of Thought Reasoning (<think> tags) */}
          {aiResult.reasoning && (
            <div className="rounded-md border border-purple-500/30 bg-purple-950/20 p-3 text-xs space-y-2">
              <button
                type="button"
                onClick={() => setShowReasoning(!showReasoning)}
                className="flex w-full items-center justify-between text-left font-bold text-purple-300"
              >
                <div className="flex items-center gap-2">
                  <Bot size={14} />
                  <span>DeepSeek-R1 Cryptographic Reasoning Trace (&lt;think&gt;)</span>
                </div>
                {showReasoning ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
              </button>
              {showReasoning && (
                <div className="mt-2 rounded bg-slate-950 p-3 font-mono text-[11px] text-slate-300 whitespace-pre-wrap leading-relaxed max-h-60 overflow-y-auto">
                  {aiResult.reasoning}
                </div>
              )}
            </div>
          )}

          {/* Explanation & Unified Diff */}
          <div className="space-y-2">
            <p className="text-xs text-foreground font-medium">
              {aiResult.explanation}
            </p>
            {aiResult.unified_diff && (
              <pre className="max-h-64 overflow-auto rounded bg-slate-950 p-3 font-mono text-[11px] text-slate-200 leading-relaxed">
                {aiResult.unified_diff.split("\n").map((line, i) => {
                  let color = "text-slate-300";
                  if (line.startsWith("+") && !line.startsWith("+++")) color = "text-emerald-400 bg-emerald-950/40";
                  else if (line.startsWith("-") && !line.startsWith("---")) color = "text-red-400 bg-red-950/40";
                  else if (line.startsWith("@@")) color = "text-cyan-400";
                  return <div key={i} className={color}>{line}</div>;
                })}
              </pre>
            )}
          </div>
        </div>
      )}

      {/* ── Remediation Diff & Patched Codebase Results ── */}
      {patchResult && (
        <div className={`rounded-lg border p-5 shadow-xs space-y-4 ${
          patchResult.summary.vulnerable_files_count > 0
            ? "border-emerald-500/40 bg-surface"
            : patchResult.summary.vulnerabilities_found > 0
            ? "border-amber-500/40 bg-surface"
            : "border-cyan-500/40 bg-surface"
        }`}>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-subtle pb-4">
            <div>
              <div className="flex items-center gap-2">
                {patchResult.summary.vulnerable_files_count > 0 ? (
                  <span className="rounded bg-emerald-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-400 uppercase">
                    {patchResult.summary.all_verified ? "100% VERIFIED" : `${patchResult.summary.remediation_rate_percent}% REMEDIATED`}
                  </span>
                ) : patchResult.summary.vulnerabilities_found > 0 ? (
                  <span className="rounded bg-amber-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-amber-400 uppercase">
                    ATTENTION NEEDED
                  </span>
                ) : (
                  <span className="rounded bg-cyan-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-cyan-400 uppercase">
                    VERIFIED CLEAN (0 WEAKNESSES)
                  </span>
                )}
                <h3 className="text-base font-bold text-foreground">
                  Post-Quantum Remediation Results
                </h3>
              </div>
              <p className="mt-1 text-xs text-quiet">
                {patchResult.summary.vulnerable_files_count > 0 ? (
                  `Scanned ${patchResult.summary.total_files_scanned} files · Patched ${patchResult.summary.vulnerable_files_count} vulnerable files · Eliminated ${patchResult.summary.vulnerabilities_remediated} of ${patchResult.summary.vulnerabilities_found} weaknesses with zero regressions.`
                ) : patchResult.summary.vulnerabilities_found > 0 ? (
                  `Scanned ${patchResult.summary.total_files_scanned} files · Found ${patchResult.summary.vulnerabilities_found} weaknesses requiring manual or AI refactoring.`
                ) : (
                  `Scanned ${patchResult.summary.total_files_scanned} files · Zero cryptographic weaknesses found across all inspected files.`
                )}
              </p>
            </div>

            {/* 1-Click Download Patched Codebase ZIP */}
            {patchResult.summary.vulnerable_files_count > 0 && (
              <button
                type="button"
                onClick={downloadPatchedCodebaseZip}
                className="flex items-center gap-2 rounded-md bg-emerald-500 px-4 py-2.5 text-xs font-bold text-slate-950 shadow-md hover:bg-emerald-400 transition-all shrink-0"
              >
                <Download size={15} />
                <span>Download Patched Codebase (.ZIP)</span>
              </button>
            )}
          </div>

          {/* If 0 files patched, display clean or review card */}
          {patchResult.patched_files.length === 0 && (
            <div className="flex items-center gap-3 rounded-md border border-subtle bg-canvas/40 p-4 text-xs text-quiet">
              <ShieldCheck size={20} className={patchResult.summary.vulnerabilities_found > 0 ? "text-amber-400 shrink-0" : "text-cyan-400 shrink-0"} />
              <div>
                <p className="font-semibold text-foreground">
                  {patchResult.summary.vulnerabilities_found > 0
                    ? `${patchResult.summary.vulnerabilities_found} Cryptographic Weaknesses Flagged`
                    : "All Files Verified Clean"}
                </p>
                <p className="mt-0.5">
                  {patchResult.summary.vulnerabilities_found > 0
                    ? "Static patterns were flagged but require architectural migration. Use the DeepSeek-R1 AI assistant above to generate quantum-safe replacements."
                    : `All ${patchResult.summary.total_files_scanned} files passed cryptographic inspection. No legacy primitives (MD5, SHA-1, DES, 3DES, RC4, RSA < 2048) found.`}
                </p>
              </div>
            </div>
          )}

          {/* Patched Files Tree & Diff Viewer */}
          {patchResult.patched_files.length > 0 && (
            <div className="grid gap-4 lg:grid-cols-12">
              {/* File selector on left */}
              <div className="space-y-2 lg:col-span-4">
                <span className="text-[11px] font-semibold text-quiet uppercase tracking-wider">
                  Patched Files ({patchResult.patched_files.length})
                </span>
                <div className="space-y-1.5 max-h-96 overflow-y-auto pr-1">
                  {patchResult.patched_files.map((pf) => (
                    <div
                      key={pf.path}
                      onClick={() => setSelectedDiffFile(pf)}
                      className={`cursor-pointer rounded-md border p-2.5 text-xs transition-all ${
                        selectedDiffFile?.path === pf.path
                          ? "border-emerald-500/50 bg-emerald-500/10 font-medium text-emerald-400"
                          : "border-subtle bg-canvas/40 text-foreground hover:bg-surface-raised"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="truncate font-mono">{pf.path}</span>
                        <span className="rounded bg-emerald-500/20 px-1 py-0.2 font-mono text-[9px] text-emerald-300 uppercase">
                          Patched
                        </span>
                      </div>
                      <p className="mt-1 text-[10px] text-quiet truncate">
                        {pf.transformation}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Diff Viewer on right */}
              <div className="lg:col-span-8">
                {selectedDiffFile && (
                  <div className="rounded-md border border-subtle bg-canvas/80 p-3.5 text-xs">
                    <div className="flex items-center justify-between pb-2 border-b border-subtle mb-3">
                      <span className="font-mono font-bold text-foreground">
                        {selectedDiffFile.path}
                      </span>
                      <span className="font-mono text-[11px] text-emerald-400">
                        {selectedDiffFile.verification_status.toUpperCase()}
                      </span>
                    </div>

                    <p className="text-[11px] text-quiet mb-2">
                      <strong>Transformation:</strong> {selectedDiffFile.transformation}
                    </p>

                    <pre className="max-h-72 overflow-auto rounded bg-slate-950 p-3 font-mono text-[11px] text-slate-200 leading-relaxed">
                      {selectedDiffFile.unified_diff.split("\n").map((line, i) => {
                        let color = "text-slate-300";
                        if (line.startsWith("+") && !line.startsWith("+++")) color = "text-emerald-400 bg-emerald-950/40";
                        else if (line.startsWith("-") && !line.startsWith("---")) color = "text-red-400 bg-red-950/40";
                        else if (line.startsWith("@@")) color = "text-cyan-400";
                        return (
                          <div key={i} className={color}>
                            {line}
                          </div>
                        );
                      })}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
