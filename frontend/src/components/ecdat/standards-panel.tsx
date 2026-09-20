"use client";

import { useState, useEffect } from "react";
import {
  ShieldCheck,
  Scale,
  ExternalLink,
  Calendar,
  AlertCircle,
  HelpCircle,
} from "lucide-react";
import { requestApi, StandardMapping } from "@/lib/api";

interface StandardsPanelProps {
  project: string;
  token: string;
}

function complianceStatus(status: string) {
  const value = status.toLowerCase();
  if (value.includes("met") || value.includes("compliant") || value.includes("ready")) return { label: "Met", className: "border-emerald-500/25 bg-emerald-500/10 text-emerald-400", Icon: ShieldCheck };
  if (value.includes("risk") || value.includes("gap") || value.includes("required") || value.includes("pending")) return { label: "At risk", className: "border-amber-500/25 bg-amber-500/10 text-amber-400", Icon: AlertCircle };
  return { label: "Unknown", className: "border-slate-500/25 bg-slate-500/10 text-quiet", Icon: HelpCircle };
}

export function StandardsPanel({ project, token }: StandardsPanelProps) {
  const [catalog, setCatalog] = useState<{
    frameworks: Array<{ name: string; status: string }>;
    mappings: StandardMapping[];
  } | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let active = true;
    async function loadStandards() {
      setLoading(true);
      try {
        const res = await requestApi<{ frameworks: Array<{ name: string; status: string }>; mappings: StandardMapping[] }>("/standards/mapping", project, token);
        if (active) setCatalog(res);
      } catch (err) {
        console.error(err);
      } finally {
        if (active) setLoading(false);
      }
    }
    void loadStandards();
    return () => { active = false; };
  }, [project, token]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col gap-2 md:flex-row md:items-center md:justify-between border-b border-subtle pb-4">
        <div>
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Scale className="text-cyan-400" size={22} />
            Standards & Regulatory Compliance Matrix
          </h2>
          <p className="text-sm text-quiet">
            Section 21: Explicit, versioned mapping of all cryptographic findings to NIST FIPS 203/204/205,
            Commercial National Security Algorithm Suite (CNSA 2.0), and OMB M-23-02 directives.
          </p>
        </div>
      </div>

      {loading && !catalog && <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4" aria-label="Loading compliance matrix">{Array.from({ length: 4 }, (_, index) => <div key={index} className="h-20 animate-pulse rounded-lg bg-surface-raised" />)}</div>}
      {/* Framework Badges */}
      {catalog && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          {catalog.frameworks.map((fw, idx) => {
            const status = complianceStatus(fw.status);
            const Icon = status.Icon;
            return <div key={idx} className="p-3.5 rounded-lg border border-subtle bg-surface">
              <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${status.className}`}><Icon size={11} />{status.label}</span>
              <div className="mt-2 text-sm font-bold text-foreground">{fw.name}</div>
            </div>;
          })}
        </div>
      )}

      {/* Standards Catalog */}
      {catalog && (
        <div className="space-y-6">
          {catalog.mappings.map((mapping, idx) => (
            <div key={idx} className="rounded-lg border border-subtle bg-surface p-5 space-y-4">
              <div className="flex flex-col md:flex-row md:items-center justify-between border-b border-subtle pb-3 gap-2">
                <div>
                  <div className="text-xs font-bold uppercase tracking-wider text-quiet">
                    {mapping.category}
                  </div>
                  <div className="text-base font-bold text-foreground">
                    {mapping.legacy_primitive} →{" "}
                    <span className="text-cyan-400">{mapping.target_standard}</span>
                  </div>
                </div>
                <span className="text-xs px-2.5 py-1 rounded bg-cyan-500/10 text-cyan-400 font-mono">
                  {mapping.security_strength_bits}-bit Post-Quantum Strength
                </span>
              </div>

              <p className="text-xs text-foreground">{mapping.guidance}</p>

              {/* Regulatory Controls Table */}
              <div className="space-y-2 pt-2">
                <span className="text-xs font-semibold uppercase tracking-wider text-quiet block">
                  Applicable Regulatory Mandates
                </span>
                <div className="grid grid-cols-1 gap-2">
                  {mapping.controls.map((ctrl, cIdx) => {
                    const status = complianceStatus(ctrl.status);
                    const Icon = status.Icon;
                    return <div
                      key={cIdx}
                      className="p-3 rounded bg-canvas border border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-foreground">{ctrl.standard}</span>
                          <span className="text-quiet">({ctrl.jurisdiction})</span>
                          <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-semibold ${status.className}`}><Icon size={11} />{status.label}</span>
                        </div>
                        <p className="text-quiet">{ctrl.requirement}</p>
                        {ctrl.deadline_or_milestone && (
                          <div className="flex items-center gap-1.5 text-amber-400 text-xs">
                            <Calendar size={12} /> Timeline: {ctrl.deadline_or_milestone}
                          </div>
                        )}
                      </div>

                      <a
                        href={ctrl.source_url}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-cyan-400 hover:underline shrink-0"
                      >
                        Official Spec <ExternalLink size={12} />
                      </a>
                    </div>;
                  })}
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
