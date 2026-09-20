"use client";

import dynamic from "next/dynamic";
import { useMemo, useState } from "react";
import { Scan } from "@/lib/api";

const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), {
  ssr: false,
  loading: () => <div className="h-72 animate-pulse rounded-md bg-surface-raised" aria-label="Loading correlation graph" />,
});

type GraphNode = { id: string; label: string; tier: string; color: string };
type GraphLink = { source: string; target: string };

const tierColor: Record<string, string> = {
  host: "var(--teal)",
  binary: "var(--ecdat-high)",
  process: "var(--ecdat-medium)",
  source: "var(--ecdat-cyan)",
  library: "var(--ecdat-low)",
};

export function CorrelationGraph({ scans }: { scans: Scan[] }) {
  const [selected, setSelected] = useState<string | null>(null);
  const graph = useMemo(() => {
    const complete = scans.filter((scan) => scan.status === "completed");
    const nodes: GraphNode[] = [
      { id: "host", label: complete.find((s) => s.kind === "network")?.result?.target || "Observed host", tier: "host", color: tierColor.host },
      { id: "binary", label: `${complete.filter((s) => s.kind === "binary").length} binary surfaces`, tier: "binary", color: tierColor.binary },
      { id: "process", label: "Cryptographic process", tier: "process", color: tierColor.process },
      { id: "source", label: `${complete.filter((s) => s.kind === "code").length} source surfaces`, tier: "source", color: tierColor.source },
      { id: "library", label: "Detected crypto libraries", tier: "library", color: tierColor.library },
    ];
    return { nodes, links: nodes.slice(1).map((node, index) => ({ source: nodes[index].id, target: node.id })) };
  }, [scans]);
  const connected = new Set<string>();
  if (selected) {
    connected.add(selected);
    graph.links.forEach((link) => {
      if (link.source === selected) connected.add(link.target);
      if (link.target === selected) connected.add(link.source);
    });
  }

  return (
    <section className="ec-panel overflow-hidden">
      <div className="panel-heading">
        <div>
          <h2>Correlation blast radius</h2>
          <p>Host → binary → process → source → library. Select a node to isolate its direct blast radius.</p>
        </div>
        <span className="count-label">{selected ? "Focus active" : "5 tiers"}</span>
      </div>
      <div className="h-72 bg-canvas/40" aria-label="Five-tier correlation graph">
        <ForceGraph2D
          graphData={graph}
          nodeLabel={(node: object) => (node as GraphNode).label}
          nodeColor={(node: object) => {
            const current = node as GraphNode;
            return !selected || connected.has(current.id) ? current.color : "var(--border)";
          }}
          nodeRelSize={6}
          linkColor={(link: object) => {
            const current = link as GraphLink;
            return !selected || (connected.has(current.source) && connected.has(current.target)) ? "var(--muted-text)" : "var(--border)";
          }}
          linkWidth={(link: object) => {
            const current = link as GraphLink;
            return selected && connected.has(current.source) && connected.has(current.target) ? 2.5 : 1;
          }}
          onNodeClick={(node: object) => {
            const id = (node as GraphNode).id;
            setSelected((current) => current === id ? null : id);
          }}
          cooldownTicks={80}
          backgroundColor="transparent"
        />
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-2 border-t border-subtle px-5 py-3 text-[11px] text-quiet">
        {graph.nodes.map((node) => <button key={node.id} onClick={() => setSelected(selected === node.id ? null : node.id)} className="inline-flex items-center gap-1.5 hover:text-foreground"><span className="h-2 w-2 rounded-full" style={{ background: node.color }} />{node.tier}</button>)}
      </div>
    </section>
  );
}
