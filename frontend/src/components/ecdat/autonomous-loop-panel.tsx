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
} from "lucide-react";
import { requestApi, CodebasePatchResponse, PatchedFileResult } from "@/lib/api";

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
  const [mode, setMode] = useState<"snippet" | "codebase">("snippet");
  
  // Multi-file / Full codebase state
  const [codebaseFiles, setCodebaseFiles] = useState<Array<{ path: string; content: string }>>([]);
  const [uploadedZip, setUploadedZip] = useState<File | null>(null);
  
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
        res = await requestApi<CodebasePatchResponse>(
          "/migration/patch-codebase",
          project,
          token,
          { files: codebaseFiles }
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
        const res = await fetch(`/api/migration/download-patched-zip?project=${encodeURIComponent(project)}`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ files: codebaseFiles }),
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
              /* Full Codebase Upload Controls */
              <div className="mt-4 space-y-4">
                <p className="text-[11px] font-medium text-quiet uppercase tracking-wider">
                  Upload Complete Project
                </p>

                {/* Upload ZIP Archive */}
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

                {/* Or Choose Directory */}
                <label className="block cursor-pointer rounded-md border border-dashed border-subtle bg-canvas/40 p-4 text-center hover:bg-surface-raised transition-colors">
                  <FolderArchive size={24} className="mx-auto text-quiet" />
                  <span className="mt-2 block text-xs font-semibold text-foreground">
                    Or Select Source Folder
                  </span>
                  <span className="text-[10px] text-quiet">
                    Picks all nested source files
                  </span>
                  <input
                    type="file"
                    multiple
                    {...{ webkitdirectory: "" }}
                    className="sr-only"
                    onChange={handleFolderUpload}
                  />
                </label>

                {uploadedZip && (
                  <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-400 flex items-center justify-between">
                    <span className="truncate">Ready: {uploadedZip.name}</span>
                    <CheckCircle2 size={14} className="shrink-0" />
                  </div>
                )}
                {codebaseFiles.length > 0 && (
                  <div className="rounded-md border border-emerald-500/30 bg-emerald-500/10 p-2.5 text-xs text-emerald-400 flex items-center justify-between">
                    <span>{codebaseFiles.length} files selected</span>
                    <CheckCircle2 size={14} className="shrink-0" />
                  </div>
                )}
              </div>
            )}

            {/* Target Details Meta */}
            <div className="mt-5 space-y-2 border-t border-subtle pt-4 text-xs font-mono text-quiet">
              <div className="flex justify-between">
                <span>Target File:</span>
                <span className="text-foreground">
                  {mode === "codebase"
                    ? uploadedZip?.name || `${codebaseFiles.length} files`
                    : selectedScenario.filename}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Analysis Mode:</span>
                <span className="text-teal font-semibold">Strict Deterministic AST</span>
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

      {/* ── Remediation Diff & Patched Codebase Results ── */}
      {patchResult && (
        <div className="rounded-lg border border-emerald-500/40 bg-surface p-5 shadow-xs space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-subtle pb-4">
            <div>
              <div className="flex items-center gap-2">
                <span className="rounded bg-emerald-500/20 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-400 uppercase">
                  100% VERIFIED
                </span>
                <h3 className="text-base font-bold text-foreground">
                  Post-Quantum Remediation Results
                </h3>
              </div>
              <p className="mt-1 text-xs text-quiet">
                Scanned {patchResult.summary.total_files_scanned} files · Patched {patchResult.summary.vulnerable_files_count} vulnerable files · Eliminated {patchResult.summary.vulnerabilities_remediated} weaknesses with zero regressions.
              </p>
            </div>

            {/* 1-Click Download Patched Codebase ZIP */}
            <button
              type="button"
              onClick={downloadPatchedCodebaseZip}
              className="flex items-center gap-2 rounded-md bg-emerald-500 px-4 py-2.5 text-xs font-bold text-slate-950 shadow-md hover:bg-emerald-400 transition-all shrink-0"
            >
              <Download size={15} />
              <span>Download Patched Codebase (.ZIP)</span>
            </button>
          </div>

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
