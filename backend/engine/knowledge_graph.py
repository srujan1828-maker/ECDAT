import networkx as nx
from typing import Dict, Any, List, Optional
from .evidence_model import EvidenceRecord
from .correlator import CrossSurfaceCorrelator, CorrelatedTopology


class CryptoKnowledgeGraph:
    """Crypto Asset Graph implementing Section 6 & 19 of the specification.

    Nodes represent assets: applications, services, libraries, algorithms, certificates, endpoints, binaries.
    Edges represent relationships: uses, implements, depends_on, protects, serves, authenticated_by.
    """

    def __init__(self):
        self.G = nx.DiGraph()
        self._initialize_base_graph()

    def _initialize_base_graph(self):
        """Seeds the graph with a realistic enterprise topology mimicking discovering

        code, live TLS services, and certificates.
        """
        # Apps
        self.G.add_node("App: AuthGateway", type="application", severity="medium")
        self.G.add_node("App: CoreBanking", type="application", severity="high")
        
        # Services
        self.G.add_node("Service: login-api", type="service", severity="critical")
        self.G.add_node("Service: transaction-api", type="service", severity="medium")
        self.G.add_node("Service: legacy-payment", type="service", severity="high")
        
        # Crypto Primitives & Certificates
        self.G.add_node("Algo: DES (56-bit)", type="algorithm", severity="critical")
        self.G.add_node("Algo: AES-256-GCM", type="algorithm", severity="low")
        self.G.add_node("Algo: RSA-1024", type="algorithm", severity="high")
        self.G.add_node("Cert: Auth-Prod-2024", type="certificate", severity="medium")
        self.G.add_node("Protocol: TLSv1.0", type="protocol", severity="critical")
        self.G.add_node("Protocol: TLSv1.3", type="protocol", severity="low")

        # Relationships (Dependencies)
        self.G.add_edge("App: AuthGateway", "Service: login-api", relationship="uses", context="Architecture dependency")
        self.G.add_edge("App: CoreBanking", "Service: transaction-api", relationship="uses", context="Architecture dependency")
        self.G.add_edge("App: CoreBanking", "Service: legacy-payment", relationship="uses", context="Architecture dependency")

        # Crypto bindings
        self.G.add_edge("Service: login-api", "Algo: DES (56-bit)", relationship="implements", context="Source Code (Hardcoded)")
        self.G.add_edge("Service: login-api", "Cert: Auth-Prod-2024", relationship="authenticated_by", context="Network Prober (Live TLS)")
        self.G.add_edge("Cert: Auth-Prod-2024", "Algo: RSA-1024", relationship="implements", context="Certificate PKI")
        self.G.add_edge("Service: legacy-payment", "Protocol: TLSv1.0", relationship="uses", context="Network Prober")
        self.G.add_edge("Service: transaction-api", "Algo: AES-256-GCM", relationship="implements", context="Source Code")
        self.G.add_edge("Service: transaction-api", "Protocol: TLSv1.3", relationship="uses", context="Network Prober")

    def add_finding(self, service: str, primitive: str, context: str, severity: str, relationship: str = "uses"):
        """Dynamically add findings from AST or Network Scanners."""
        if not self.G.has_node(service):
            self.G.add_node(service, type="service", severity=severity)
        if not self.G.has_node(primitive):
            self.G.add_node(primitive, type="algorithm", severity=severity)
        
        self.G.add_edge(service, primitive, context=context, relationship=relationship)

    def load_from_topology(self, topology: CorrelatedTopology):
        """Rebuilds the internal graph from a correlated topology."""
        self.G.clear()
        for node in topology.nodes:
            self.G.add_node(
                node.id,
                label=node.label,
                type=node.type,
                severity=node.severity,
                surface=node.surface,
                quantum_vulnerable=node.quantum_vulnerable,
                metadata=node.metadata
            )
        for link in topology.links:
            self.G.add_edge(
                link.source,
                link.target,
                relationship=link.relationship,
                confidence=link.confidence,
                context=link.context,
                evidence_ids=link.evidence_ids
            )

    @classmethod
    def from_evidence_records(cls, records: List[EvidenceRecord], app_name: str = "Enterprise System") -> "CryptoKnowledgeGraph":
        correlator = CrossSurfaceCorrelator()
        correlator.ingest_records(records)
        topo = correlator.correlate(default_app_name=app_name)
        graph = cls()
        graph.load_from_topology(topo)
        return graph

    @classmethod
    def from_scans(cls, scan_records: List[Dict[str, Any]], app_name: str = "Enterprise System") -> "CryptoKnowledgeGraph":
        correlator = CrossSurfaceCorrelator()
        correlator.ingest_scan_results(scan_records)
        topo = correlator.correlate(default_app_name=app_name)
        graph = cls()
        graph.load_from_topology(topo)
        return graph

    def compute_blast_radius(self, target_node: str) -> List[str]:
        """Calculates blast radius (Module 4): if a primitive (e.g., RSA-1024) is

        cracked, which upstream services and apps are compromised?
        Uses reverse graph traversal on directed edges.
        """
        if not self.G.has_node(target_node):
            return []
        impacted_nodes = list(nx.ancestors(self.G, target_node))
        return sorted(impacted_nodes)

    def export_for_ui(self) -> Dict[str, Any]:
        """Exports the NetworkX graph to the React Force Graph format."""
        nodes = []
        links = []
        
        for node, data in self.G.nodes(data=True):
            label = data.get("label") or (node.split(": ")[-1] if ": " in node else node)
            nodes.append({
                "id": node,
                "label": label,
                "group": data.get("type", "unknown"),
                "severity": data.get("severity", "low"),
                "surface": data.get("surface", "unknown"),
                "quantum_vulnerable": data.get("quantum_vulnerable"),
                "blast_radius": self.compute_blast_radius(node),
                "metadata": data.get("metadata", {})
            })
            
        for source, target, data in self.G.edges(data=True):
            links.append({
                "source": source,
                "target": target,
                "relationship": data.get("relationship", "uses"),
                "confidence": data.get("confidence", "observed"),
                "label": data.get("context") or data.get("relationship", "")
            })
            
        return {
            "nodes": nodes,
            "links": links
        }

    def get_kpis(self) -> Dict[str, Any]:
        """Calculates dynamic KPIs based on graph state."""
        critical_count = sum(1 for _, d in self.G.nodes(data=True) if d.get("severity") in ("critical", "CRITICAL"))
        total_findings = sum(1 for _, d in self.G.nodes(data=True) if d.get("type") in ["algorithm", "protocol", "certificate"])
        
        qv_certs = sum(
            1 for n, d in self.G.nodes(data=True)
            if d.get("quantum_vulnerable") is True or (d.get("type") == "certificate" and ("RSA" in str(n) or "DES" in str(n)))
        )
        
        return {
            "total_findings": total_findings,
            "critical": critical_count,
            "quantum_vulnerable_certs": qv_certs,
            "est_migration_effort": f"{critical_count * 2} weeks" if critical_count > 0 else "0 weeks"
        }


# Global singleton for demo
kg = CryptoKnowledgeGraph()
