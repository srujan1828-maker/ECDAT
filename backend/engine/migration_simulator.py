from datetime import datetime, timezone
from typing import Dict, Any, List

def simulate_pqc_migration_roadmap(
    x_shelf_life: int,
    y_migration_time: int,
    z_crqc_horizon: int,
    critical_findings_count: int = 3,
    qv_certs_count: int = 2
) -> Dict[str, Any]:
    """
    Generates an executive PQC Migration Roadmap and phased Gantt timeline
    aligned with NIST FIPS 203/204/205, NSA CNSA 2.0, and India's National Quantum Mission (NQM).
    """
    current_year = datetime.now(timezone.utc).year
    crqc_target_year = current_year + z_crqc_horizon
    migration_completion_year = current_year + y_migration_time
    total_exposure = (x_shelf_life + y_migration_time) - z_crqc_horizon
    is_urgent = total_exposure > 0

    # Person-month calculation based on findings and migration span
    base_person_months = (critical_findings_count * 2.5) + (qv_certs_count * 1.5) + (y_migration_time * 3.0)
    person_months = max(6, int(base_person_months))
    est_budget_inr = f"₹{person_months * 1.8:.1f} Lakhs"

    # Three-Phase Implementation Roadmap
    phases: List[Dict[str, Any]] = [
        {
            "phase": "Phase 1: Perimeter Hybrid KEM (HNDL Defense)",
            "timeline": f"Q1 {current_year} – Q4 {current_year}",
            "duration_months": min(12, y_migration_time * 6),
            "priority": "IMMEDIATE" if is_urgent else "HIGH",
            "pqc_standard": "NIST FIPS 203 (ML-KEM-768)",
            "scope": "Edge TLS Ingress, API Gateways, Microservice Inter-Connects",
            "action_items": [
                "Deploy X25519 + ML-KEM-768 hybrid key exchange on Cloudflare/NGINX/Envoy ingress.",
                "Enforce 256-bit symmetric AEAD baseline (AES-256-GCM) on all externally reachable routes.",
                "Verify and eliminate all static RSA key exchanges to prevent retrospective decryption."
            ],
            "milestone": "100% Perimeter Defense against Harvest Now, Decrypt Later (HNDL)."
        },
        {
            "phase": "Phase 2: PKI & Quantum-Safe Digital Signatures",
            "timeline": f"Q1 {current_year + 1} – Q4 {current_year + 1}",
            "duration_months": 12,
            "priority": "HIGH",
            "pqc_standard": "NIST FIPS 204 (ML-DSA) & FIPS 205 (SLH-DSA)",
            "scope": "Internal Root & Intermediate CAs, Code Signing, Document Signing",
            "action_items": [
                "Issue hybrid dual-certificate chains (RSA-3072 + ML-DSA-65) for internal services.",
                "Update software artifact signing pipelines to stateful/stateless hash signatures (SLH-DSA).",
                "Integrate hardware security modules (HSMs) supporting PQC firmware algorithms."
            ],
            "milestone": "Full cryptographic authentication and trust hierarchy quantum resilience."
        },
        {
            "phase": "Phase 3: Data At Rest & Symmetric Key Doubling",
            "timeline": f"Q1 {current_year + 2} – Q4 {min(crqc_target_year, current_year + max(2, y_migration_time))}",
            "duration_months": max(12, (y_migration_time - 2) * 12),
            "priority": "MEDIUM",
            "pqc_standard": "FIPS 197 AES-256 & CNSA 2.0 Baseline",
            "scope": "Databases, Long-Term Cold Storage, Secret Managers, Backup Tapes",
            "action_items": [
                "Re-encrypt archive storage from AES-128 to AES-256-GCM for Grover resistance.",
                "Decommission legacy cryptographic libraries (BouncyCastle < v1.78, OpenSSL 1.0.x).",
                "Automate CBOM continuous monitoring into CI/CD security pipelines."
            ],
            "milestone": "Zero legacy cryptographic primitives across entire enterprise inventory."
        }
    ]

    return {
        "current_year": current_year,
        "crqc_target_year": crqc_target_year,
        "migration_completion_year": migration_completion_year,
        "total_exposure_years": max(0, total_exposure),
        "posture_urgency": "CRITICAL" if total_exposure > 2 else ("ELEVATED" if is_urgent else "STABLE"),
        "person_months": person_months,
        "estimated_budget": est_budget_inr,
        "phases": phases,
        "regulatory_deadlines": [
            {"framework": "NSA CNSA 2.0", "target": "2030", "requirement": "Mandatory ML-KEM/ML-DSA on all national security systems"},
            {"framework": "India National Quantum Mission (NQM)", "target": "2028", "requirement": "Migration roadmap and CBOM compliance for critical sectors"},
            {"framework": "NIST SP 800-131A", "target": "2025-2030", "requirement": "Deprecation of 112-bit security keys (RSA-2048 transition)"}
        ]
    }
