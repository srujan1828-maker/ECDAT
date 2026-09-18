"""
ECDAT V4 Multi-Modal Evidence Fusion Engine.

Principles:
1. Associates multi-source observations (source, dependency, binary, TLS, X.509, PQC) into unified CryptoAssets.
2. Distinct corroboration statuses: SINGLE_SOURCE, CORROBORATED, CONTRADICTED, INCONCLUSIVE.
3. NEVER averages confidence into an opaque score.
4. Preserves highest evidence level (E0..E5) independently of confidence.
5. Emits deterministic, transparent "Why Was This Detected?" explanations based on real evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
import re

from .evidence_model import Evidence, EvidenceLevel, EvidenceState, ObservationType
from .asset_graph import AssetGraphService, AssetType, CryptoAsset, RelationshipType


class CorroborationStatus(str, Enum):
    SINGLE_SOURCE = "SINGLE_SOURCE"
    CORROBORATED = "CORROBORATED"
    CONTRADICTED = "CONTRADICTED"
    INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class CorroborationResult:
    fused_status: CorroborationStatus
    highest_level: EvidenceLevel
    combined_confidence: float
    explanation: str
    contradictions: List[str] = field(default_factory=list)


def extract_primitive_canonical_name(text: str) -> Tuple[str, Optional[int]]:
    """Normalizes cryptographic names into canonical algorithm and key size."""
    upper = text.strip().upper()
    key_size = None

    # Key size extraction
    m_bits = re.search(r"(\d{3,4})", upper)
    if m_bits:
        val = int(m_bits.group(1))
        if val in (56, 64, 112, 128, 192, 256, 384, 512, 1024, 2048, 3072, 4096):
            key_size = val

    if "MD5" in upper:
        return "MD5", 128
    if "SHA-1" in upper or "SHA1" in upper:
        return "SHA-1", 160
    if "SHA-256" in upper or "SHA256" in upper:
        return "SHA-256", 256
    if "SHA-384" in upper or "SHA384" in upper:
        return "SHA-384", 384
    if "SHA-512" in upper or "SHA512" in upper:
        return "SHA-512", 512
    if "SHA-3" in upper or "SHA3" in upper:
        return "SHA-3", 256
    if "3DES" in upper or "TRIPLEDES" in upper or "DES3" in upper or "DESEDE" in upper:
        return "3DES", 112
    if "DES" in upper and "3DES" not in upper:
        return "DES", 56
    if "RC4" in upper or "ARC4" in upper:
        return "RC4", 128
    if "AES-GCM" in upper or "AES_256_GCM" in upper:
        return "AES-GCM", key_size or 256
    if "AES-CBC" in upper or "AES_256_CBC" in upper:
        return "AES-CBC", key_size or 256
    if "AES-ECB" in upper or "ECB" in upper:
        return "AES-ECB", key_size or 128
    if "AES" in upper:
        return "AES", key_size or 256
    if "RSA" in upper:
        return f"RSA-{key_size}" if key_size else "RSA", key_size
    if "ECDSA" in upper:
        return "ECDSA", key_size or 256
    if "ED25519" in upper:
        return "Ed25519", 256
    if "X25519" in upper:
        return "X25519", 256
    if "ML-KEM" in upper or "MLKEM" in upper:
        return "ML-KEM", key_size or 768
    if "ML-DSA" in upper or "MLDSA" in upper:
        return "ML-DSA", key_size or 65
    if "SLH-DSA" in upper or "SLHDSA" in upper:
        return "SLH-DSA", key_size or 128

    return text.strip(), key_size


@dataclass
class FusedAssetCandidate:
    canonical_name: str
    asset_type: AssetType
    algorithm: str
    key_size: Optional[int]
    evidence_items: List[Evidence] = field(default_factory=list)
    contradictions: List[str] = field(default_factory=list)

    @property
    def highest_level(self) -> EvidenceLevel:
        if not self.evidence_items:
            return EvidenceLevel.E0
        return max(self.evidence_items, key=lambda e: e.level.rank).level

    @property
    def max_confidence(self) -> float:
        if not self.evidence_items:
            return 0.0
        return max(e.confidence for e in self.evidence_items)

    @property
    def source_engines(self) -> Set[str]:
        return {e.source_engine for e in self.evidence_items}

    @property
    def status(self) -> str:
        if self.contradictions:
            return "CONTRADICTED"
        if len(self.source_engines) >= 2:
            return "CORROBORATED"
        if len(self.evidence_items) == 1:
            return "SINGLE_SOURCE"
        return "SINGLE_SOURCE"


class EvidenceFusionEngine:
    def __init__(self, graph_service: Optional[AssetGraphService] = None):
        self.graph = graph_service

    def fuse_scan_evidence(
        self,
        project: str,
        scan_id: str,
        evidence_list: List[Evidence],
    ) -> List[CryptoAsset]:
        """
        Groups evidence into coherent CryptoAssets, identifies corroboration or
        contradictions, updates graph nodes and relationships.
        """
        # Step 1: Bucket evidence by canonical target
        asset_buckets: Dict[str, FusedAssetCandidate] = {}

        for ev in evidence_list:
            raw_target = ev.symbol or ev.description
            # Detect observation category
            if ev.observation_type == ObservationType.X509_CERTIFICATE:
                cert_fingerprint = ev.raw_details.get("sha256") or ev.symbol or "x509_cert"
                bucket_key = f"cert:{cert_fingerprint}"
                name = ev.symbol or f"Certificate ({cert_fingerprint[:16]}...)"
                algo, key_size = extract_primitive_canonical_name(ev.description)
                a_type = AssetType.CERTIFICATE
            elif ev.observation_type in (ObservationType.TLS_NEGOTIATION, ObservationType.PQC_NEGOTIATION):
                endpoint = ev.raw_details.get("target") or "endpoint"
                algo, key_size = extract_primitive_canonical_name(ev.symbol or ev.description)
                bucket_key = f"tls:{algo}:{endpoint}"
                name = f"{algo} ({endpoint})"
                a_type = AssetType.PROTOCOL
            elif ev.observation_type in (ObservationType.DEPENDENCY_DECLARATION, ObservationType.DEPENDENCY_LOCKFILE):
                dep_name = ev.symbol or "dependency"
                bucket_key = f"dep:{dep_name.lower()}"
                name = dep_name
                algo, key_size = extract_primitive_canonical_name(dep_name)
                a_type = AssetType.DEPENDENCY
            else:
                algo, key_size = extract_primitive_canonical_name(raw_target)
                bucket_key = f"algo:{algo}"
                name = algo
                a_type = AssetType.ALGORITHM

            if bucket_key not in asset_buckets:
                asset_buckets[bucket_key] = FusedAssetCandidate(
                    canonical_name=name,
                    asset_type=a_type,
                    algorithm=algo,
                    key_size=key_size,
                )
            asset_buckets[bucket_key].evidence_items.append(ev)

        # Step 2: Cross-check for contradictions between static and dynamic observations
        # Example: static source code configures RSA while live TLS negotiation observed ECDSA
        tls_algos = {
            c.algorithm for c in asset_buckets.values()
            if c.asset_type == AssetType.PROTOCOL and c.highest_level == EvidenceLevel.E5
        }
        for bucket in asset_buckets.values():
            if bucket.asset_type == AssetType.ALGORITHM and "RSA" in bucket.algorithm:
                if any("ECDSA" in t or "Ed25519" in t for t in tls_algos) and not any("RSA" in t for t in tls_algos):
                    contradiction_note = (
                        "Static configuration/source references RSA, but live TLS endpoint "
                        f"negotiated modern elliptic curve keys ({', '.join(tls_algos)})."
                    )
                    bucket.contradictions.append(contradiction_note)

        # Step 3: Persist fused assets into AssetGraph
        created_assets: List[CryptoAsset] = []

        for bucket in asset_buckets.values():
            explanation = self._build_why_detected_explanation(bucket)
            asset = self.graph.upsert_asset(
                project=project,
                asset_type=bucket.asset_type,
                name=bucket.canonical_name,
                algorithm=bucket.algorithm,
                key_size=bucket.key_size,
                scan_id=scan_id,
                fused_status=bucket.status,
                highest_evidence_level=bucket.highest_level.value,
                confidence=bucket.max_confidence,
                explanation=explanation,
            )

            # Bind evidence to the asset
            for ev in bucket.evidence_items:
                self.graph.add_evidence(asset.id, ev, project)
                # Link asset with evidence via graph edge
                self.graph.add_relationship(
                    project=project,
                    source_id=asset.id,
                    source_type=asset.asset_type,
                    relationship=RelationshipType.EVIDENCED_BY,
                    target_id=ev.id,
                    target_type="EVIDENCE",
                    scan_id=scan_id,
                    evidence_id=ev.id,
                    confidence=ev.confidence,
                )

            # Link contextual relationships between dependencies, algorithms, and endpoints
            if bucket.asset_type == AssetType.CERTIFICATE and bucket.algorithm:
                # Find matching algorithm asset
                algo_matches = self.graph.find_assets_by_algorithm(bucket.algorithm, project)
                for matched in algo_matches:
                    if matched.id != asset.id:
                        self.graph.add_relationship(
                            project=project,
                            source_id=asset.id,
                            source_type=asset.asset_type,
                            relationship=RelationshipType.IMPLEMENTS,
                            target_id=matched.id,
                            target_type=matched.asset_type,
                            scan_id=scan_id,
                            confidence=1.0,
                        )

            created_assets.append(asset)

        return created_assets

    def _build_why_detected_explanation(self, candidate: FusedAssetCandidate) -> str:
        """Generates evidence-backed 'Why Was This Detected?' rationale."""
        reasons = []
        for ev in candidate.evidence_items:
            loc = f" in {ev.file_path}:{ev.line_start}" if ev.file_path and ev.line_start else (
                f" at offset {ev.byte_offset}" if ev.byte_offset else ""
            )
            reasons.append(
                f"• [{ev.level.value} | {ev.state.value}] {ev.source_engine}: {ev.description}{loc} "
                f"(confidence: {int(ev.confidence * 100)}%)"
            )

        if candidate.contradictions:
            reasons.append("\nContradictory Observations:")
            for c in candidate.contradictions:
                reasons.append(f"⚠️ {c}")

        summary = (
            f"Detected {candidate.canonical_name} ({candidate.status}) with highest evidence "
            f"{candidate.highest_level.label} across {len(candidate.source_engines)} independent engine(s).\n"
            + "\n".join(reasons)
        )
        return summary

    def compute_corroboration(self, evidence_items: List[Evidence]) -> CorroborationResult:
        if not evidence_items:
            return CorroborationResult(
                fused_status=CorroborationStatus.INCONCLUSIVE,
                highest_level=EvidenceLevel.E0,
                combined_confidence=0.0,
                explanation="No evidence provided.",
                contradictions=[],
            )

        contradictions: List[str] = []
        # Check metadata contradictions
        primitives = {e.metadata.get("primitive") for e in evidence_items if e.metadata and e.metadata.get("primitive")}
        if len(primitives) > 1:
            contradictions.append(f"Contradictory cryptographic primitives observed: {', '.join(sorted(str(p) for p in primitives))}")

        # Check static vs dynamic contradictions
        static_texts = [e.description for e in evidence_items if e.level in (EvidenceLevel.E1, EvidenceLevel.E2, EvidenceLevel.E3)]
        dynamic_texts = [e.description for e in evidence_items if e.level in (EvidenceLevel.E4, EvidenceLevel.E5)]
        if any("RSA" in s for s in static_texts) and any("ECDSA" in d for d in dynamic_texts) and not any("RSA" in d for d in dynamic_texts):
            contradictions.append("Static observation references RSA while live dynamic observation detected ECDSA")

        source_engines = {e.source_engine for e in evidence_items}
        highest_level = max((e.level for e in evidence_items), key=lambda l: l.rank)

        # Independent probability fusion: 1 - product(1 - c_i)
        unconf = 1.0
        for e in evidence_items:
            unconf *= (1.0 - min(max(e.confidence, 0.0), 1.0))
        combined_confidence = round(1.0 - unconf, 4)

        if contradictions:
            status = CorroborationStatus.CONTRADICTED
        elif len(source_engines) >= 2 or len(evidence_items) >= 2:
            status = CorroborationStatus.CORROBORATED
        elif len(evidence_items) == 1:
            status = CorroborationStatus.SINGLE_SOURCE
        else:
            status = CorroborationStatus.INCONCLUSIVE

        explanation = self.generate_explanation(evidence_items, status, contradictions)
        return CorroborationResult(
            fused_status=status,
            highest_level=highest_level,
            combined_confidence=combined_confidence,
            explanation=explanation,
            contradictions=contradictions,
        )

    def generate_explanation(
        self,
        evidence_items: List[Evidence],
        status: CorroborationStatus | str,
        contradictions: Optional[List[str]] = None,
    ) -> str:
        status_val = status.value if isinstance(status, CorroborationStatus) else str(status)
        lines: List[str] = []

        if status_val == CorroborationStatus.CONTRADICTED.value or contradictions:
            lines.append("⚠️ CONTRADICTION DETECTED across multi-modal observations.")
            if contradictions:
                for c in contradictions:
                    lines.append(f"  • {c}")
        elif status_val == CorroborationStatus.CORROBORATED.value:
            lines.append(f"Corroborated across {len({e.source_engine for e in evidence_items})} sources.")
        elif status_val == CorroborationStatus.SINGLE_SOURCE.value:
            lines.append("Single-source observation.")

        for ev in evidence_items:
            rule_str = f" [{ev.rule_id}]" if ev.rule_id else ""
            loc = f" in {ev.file_path}:{ev.line_start}" if ev.file_path and ev.line_start else ""
            lines.append(
                f"• [{ev.level.value} | {ev.state.value}] {ev.source_engine}{rule_str}: {ev.description}{loc} "
                f"(confidence: {int(ev.confidence * 100)}%)"
            )

        return "\n".join(lines)

    def fuse_asset_findings(
        self,
        project: str,
        scan_id: str,
        asset_name: str,
        algorithm: str,
        evidence_items: List[Evidence],
        asset_type: AssetType = AssetType.ALGORITHM,
    ) -> Dict[str, Any]:
        result = self.compute_corroboration(evidence_items)
        asset_dict = {
            "project": project,
            "scan_id": scan_id,
            "name": asset_name,
            "algorithm": algorithm,
            "asset_type": asset_type.value if hasattr(asset_type, "value") else str(asset_type),
            "fused_status": result.fused_status.value,
            "highest_evidence_level": result.highest_level.value,
            "confidence": result.combined_confidence,
            "explanation": result.explanation,
            "contradictions": result.contradictions,
        }
        if self.graph:
            asset = self.graph.upsert_asset(
                project=project,
                asset_type=asset_type,
                name=asset_name,
                algorithm=algorithm,
                scan_id=scan_id,
                fused_status=result.fused_status.value,
                highest_evidence_level=result.highest_level.value,
                confidence=result.combined_confidence,
                explanation=result.explanation,
            )
            for ev in evidence_items:
                self.graph.add_evidence(asset.id, ev, project)
            asset_dict["id"] = asset.id
        return asset_dict
