"""
ECDAT V4 Unified Evidence Model & Provenance Engine.

Core Principles:
1. WHAT WAS MEASURED != WHAT WAS INFERRED != WHAT WAS ESTIMATED != WHAT CANNOT BE INDEPENDENTLY VERIFIED.
2. Evidence level (E0..E5) is strictly distinct from statistical confidence (0.0..1.0).
3. Every finding links back to an immutable, reproducible provenance record.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import hashlib
import json
from typing import Any, Dict, List, Optional
import uuid


class EvidenceState(str, Enum):
    MEASURED = "MEASURED"
    INFERRED = "INFERRED"
    ESTIMATED = "ESTIMATED"
    DECLARED = "DECLARED"
    UNMEASURED = "UNMEASURED"
    EXTRAPOLATED = "EXTRAPOLATED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_IN_OBSERVED_SCOPE = "NOT_IN_OBSERVED_SCOPE"


class EvidenceLevel(str, Enum):
    E0 = "E0"  # Unmeasured / no evidence collected
    E1 = "E1"  # Pattern or heuristic candidate detected
    E2 = "E2"  # Structured asset detected
    E3 = "E3"  # Actual reference / API use confirmed
    E4 = "E4"  # Reachability or execution path confirmed
    E5 = "E5"  # Live protocol / network behavior observed

    @property
    def rank(self) -> int:
        return int(self.value[1])

    @property
    def label(self) -> str:
        descriptions = {
            "E0": "Unmeasured / no evidence collected",
            "E1": "Pattern or heuristic candidate detected",
            "E2": "Structured asset detected",
            "E3": "Actual reference / API use confirmed",
            "E4": "Reachability or execution path confirmed",
            "E5": "Live protocol / network behavior observed",
        }
        return f"{self.value} — {descriptions[self.value]}"


LEVEL_RANK: Dict[EvidenceLevel, int] = {
    EvidenceLevel.E0: 0,
    EvidenceLevel.E1: 1,
    EvidenceLevel.E2: 2,
    EvidenceLevel.E3: 3,
    EvidenceLevel.E4: 4,
    EvidenceLevel.E5: 5,
}


class ArtifactType(str, Enum):
    SOURCE_FILE = "SOURCE_FILE"
    BINARY = "BINARY"
    FIRMWARE = "FIRMWARE"
    NETWORK_ENDPOINT = "NETWORK_ENDPOINT"
    CONFIG_FILE = "CONFIG_FILE"
    CERTIFICATE = "CERTIFICATE"
    CONTAINER_IMAGE = "CONTAINER_IMAGE"
    SYSTEM_PACKAGE = "SYSTEM_PACKAGE"


class ObservationType(str, Enum):
    SOURCE_PATTERN = "SOURCE_PATTERN"
    SOURCE_API_USE = "SOURCE_API_USE"
    SOURCE_IMPORT = "SOURCE_IMPORT"
    SOURCE_DATAFLOW = "SOURCE_DATAFLOW"
    DEPENDENCY_DECLARATION = "DEPENDENCY_DECLARATION"
    DEPENDENCY_LOCKFILE = "DEPENDENCY_LOCKFILE"
    BINARY_SIGNATURE = "BINARY_SIGNATURE"
    BINARY_SYMBOL = "BINARY_SYMBOL"
    BINARY_FUNCTION = "BINARY_FUNCTION"
    BINARY_REFERENCE = "BINARY_REFERENCE"
    HARDCODED_KEY = "HARDCODED_KEY"
    FIRMWARE_CONTENT = "FIRMWARE_CONTENT"
    TLS_NEGOTIATION = "TLS_NEGOTIATION"
    TLS_CONFIGURATION = "TLS_CONFIGURATION"
    X509_CERTIFICATE = "X509_CERTIFICATE"
    SSH_NEGOTIATION = "SSH_NEGOTIATION"
    PQC_NEGOTIATION = "PQC_NEGOTIATION"
    QUIC_NEGOTIATION = "QUIC_NEGOTIATION"
    PROTOCOL_OBSERVATION = "PROTOCOL_OBSERVATION"
    RUNTIME_CALL = "RUNTIME_CALL"
    HTTP_HEADER = "HTTP_HEADER"
    COOKIE = "COOKIE"
    THIRD_PARTY_RESOURCE = "THIRD_PARTY_RESOURCE"
    CONFIGURATION = "CONFIGURATION"
    MANIFEST = "MANIFEST"
    USER_SUPPLIED = "USER_SUPPLIED"
    SSH_CAPABILITY = "SSH_CAPABILITY"


@dataclass
class Provenance:
    input_hash: str = ""
    source_engine: str = ""
    engine_version: str = "4.0.0"
    scan_id: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scanner_version: str = "4.0.0"
    artifact_hash: Optional[str] = None
    rule_id: Optional[str] = None
    rule_version: Optional[str] = None
    location: Optional[str] = None
    environment: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def hash(self) -> str:
        serialized = json.dumps(self.to_dict(), sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


@dataclass
class Evidence:
    state: EvidenceState
    level: EvidenceLevel
    confidence: float
    source_engine: str
    observation_type: ObservationType
    artifact_type: str | ArtifactType
    description: str
    provenance: Provenance
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    engine_version: str = "4.0.0"
    rule_id: Optional[str] = None
    rule_version: Optional[str] = None
    artifact_id: Optional[str] = None
    location: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    byte_offset: Optional[str] = None
    function_name: Optional[str] = None
    symbol: Optional[str] = None
    limitations: List[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    supporting: List[str] = field(default_factory=list)
    contradicting: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # Validate confidence is strictly bound to [0.0, 1.0]
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if isinstance(self.state, str):
            self.state = EvidenceState(self.state)
        if isinstance(self.level, str):
            self.level = EvidenceLevel(self.level)
        if isinstance(self.observation_type, str):
            self.observation_type = ObservationType(self.observation_type)

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["state"] = self.state.value
        res["level"] = self.level.value
        res["observation_type"] = self.observation_type.value
        res["level_label"] = self.level.label
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Evidence:
        d = dict(data)
        prov_data = d.pop("provenance")
        if isinstance(prov_data, dict):
            provenance = Provenance(**prov_data)
        else:
            provenance = prov_data
        d.pop("level_label", None)
        return cls(provenance=provenance, **d)
