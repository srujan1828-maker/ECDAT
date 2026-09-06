import networkx as nx
from typing import Dict, Any, List

class CryptoKnowledgeGraph:
    def __init__(self):
        self.G = nx.DiGraph()
        self._initialize_base_graph()

    def _initialize_base_graph(self):
        """
        Seeds the graph with a realistic enterprise topology mimicking discovering
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
        self.G.add_edge("App: AuthGateway", "Service: login-api")
        self.G.add_edge("App: CoreBanking", "Service: transaction-api")
        self.G.add_edge("App: CoreBanking", "Service: legacy-payment")

        # Crypto bindings
        self.G.add_edge("Service: login-api", "Algo: DES (56-bit)", context="Source Code (Hardcoded)")
        self.G.add_edge("Service: login-api", "Cert: Auth-Prod-2024", context="Network Prober (Live TLS)")
        self.G.add_edge("Cert: Auth-Prod-2024", "Algo: RSA-1024", context="Certificate PKI")
        self.G.add_edge("Service: legacy-payment", "Protocol: TLSv1.0", context="Network Prober")
        self.G.add_edge("Service: transaction-api", "Algo: AES-256-GCM", context="Source Code")
        self.G.add_edge("Service: transaction-api", "Protocol: TLSv1.3", context="Network Prober")

    def add_finding(self, service: str, primitive: str, context: str, severity: str):
        """Dynamically add findings from AST or Network Scanners."""
        if not self.G.has_node(service):
            self.G.add_node(service, type="service", severity=severity)
        if not self.G.has_node(primitive):
            self.G.add_node(primitive, type="algorithm", severity=severity)
        
        self.G.add_edge(service, primitive, context=context)

    def compute_blast_radius(self, target_node: str) -> List[str]:
        """
        Calculates blast radius (Module 4): if a primitive (e.g., RSA-1024) is 
        cracked, which upstream services and apps are compromised?
        Uses reverse graph traversal on directed edges.
        """
        if not self.G.has_node(target_node):
            return []
        
        # We need upstream nodes that rely on this target node.
        # Since edges are App -> Service -> Crypto, we traverse predecessors.
        impacted_nodes = list(nx.ancestors(self.G, target_node))
        return impacted_nodes

    def export_for_ui(self) -> Dict[str, Any]:
        """
        Exports the NetworkX graph to the React Force Graph format.
        """
        nodes = []
        links = []
        
        for node, data in self.G.nodes(data=True):
            nodes.append({
                "id": node,
                "label": node.split(": ")[-1] if ": " in node else node,
                "group": data.get("type", "unknown"),
                "severity": data.get("severity", "low"),
                "blast_radius": self.compute_blast_radius(node)
            })
            
        for source, target, data in self.G.edges(data=True):
            links.append({
                "source": source,
                "target": target,
                "label": data.get("context", "")
            })
            
        return {
            "nodes": nodes,
            "links": links
        }

    def get_kpis(self) -> Dict[str, Any]:
        """Calculates dynamic KPIs based on graph state."""
        critical_count = sum(1 for n, d in self.G.nodes(data=True) if d.get("severity") == "critical")
        total_findings = sum(1 for n, d in self.G.nodes(data=True) if d.get("type") in ["algorithm", "protocol", "certificate"])
        
        # For demo purposes, identify RSA or older as QV (Quantum Vulnerable)
        qv_certs = sum(1 for n, d in self.G.nodes(data=True) if "RSA" in n or "DES" in n)
        
        return {
            "total_findings": total_findings,
            "critical": critical_count,
            "quantum_vulnerable_certs": qv_certs,
            "est_migration_effort": f"{critical_count * 2} weeks"
        }

# Global singleton for demo
kg = CryptoKnowledgeGraph()
