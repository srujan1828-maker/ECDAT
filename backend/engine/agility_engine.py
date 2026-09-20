from typing import Dict, Any, List

def calculate_crypto_agility(
    hardcoded_primitives_count: int,
    abstracted_primitives_count: int,
    has_provider_abstraction: bool,
    has_pqc_hybrid_support: bool,
    automated_cert_rotation: bool,
    uses_config_driven_crypto: bool
) -> Dict[str, Any]:
    """
    Computes the Cryptographic Agility Index (CAI) for an application/service
    as defined in SIH26164 / NTRO Architecture (Module 7).
    
    Score range: 0.00 (Rigid/Hardcoded) to 1.00 (Fully Agile & PQC-Ready).
    """
    # 1. Primitive Decoupling Score (0.0 to 0.25)
    total_prims = hardcoded_primitives_count + abstracted_primitives_count
    if total_prims == 0:
        decoupling_score = 0.20
    else:
        decoupling_ratio = abstracted_primitives_count / total_prims
        decoupling_score = round(decoupling_ratio * 0.25, 3)

    # 2. Provider Abstraction Score (0.0 to 0.25)
    # Checks if JCE, OpenSSL EVP, or WebCrypto provider interfaces are used
    provider_score = 0.25 if has_provider_abstraction else 0.05

    # 3. KEM & Hybrid Agility Score (0.0 to 0.25)
    # Checks if Key Encapsulation can be swapped independently of bulk encryption
    kem_score = 0.25 if has_pqc_hybrid_support else (0.15 if uses_config_driven_crypto else 0.05)

    # 4. Lifecycle & Certificate Automation (0.0 to 0.25)
    lifecycle_score = 0.25 if automated_cert_rotation else 0.05

    # Total Agility Index
    total_cai = round(decoupling_score + provider_score + kem_score + lifecycle_score, 2)

    # Agility Tier classification
    if total_cai >= 0.80:
        tier = "PQC AGILE"
        badge_color = "emerald"
        posture = "Quantum-Agile Architecture: Cryptographic primitives and providers can be upgraded via configuration with minimal or zero code refactoring."
    elif total_cai >= 0.50:
        tier = "PARTIALLY AGILE"
        badge_color = "amber"
        posture = "Moderate Agility: Some abstraction layers exist, but key encapsulation and primitive selection still require code-level modifications."
    else:
        tier = "RIGID / HARDCODED"
        badge_color = "red"
        posture = "Cryptographically Inflexible: Direct, hardcoded primitive calls detected. Migrating to NIST Post-Quantum standards will require substantial code refactoring."

    # Pillar Breakdown
    pillars = [
        {
            "name": "Primitive Decoupling",
            "score": round(decoupling_score / 0.25 * 100, 1),
            "max": 100,
            "status": "Configuration-Driven" if decoupling_score > 0.15 else "Hardcoded In Line",
            "recommendation": "Externalize cipher suite strings into environment configurations or KMS policies."
        },
        {
            "name": "Provider & API Abstraction",
            "score": round(provider_score / 0.25 * 100, 1),
            "max": 100,
            "status": "Standardized Provider (EVP/JCE)" if has_provider_abstraction else "Direct Primitive Coupling",
            "recommendation": "Adopt provider interfaces (e.g. OpenSSL 3.0 Providers, JCE, PKCS#11) for plug-and-play PQC algorithms."
        },
        {
            "name": "KEM & PQC Modularity",
            "score": round(kem_score / 0.25 * 100, 1),
            "max": 100,
            "status": "Hybrid PQC Ready" if has_pqc_hybrid_support else "Classical Bound",
            "recommendation": "Separate Key Encapsulation (KEM) logic from AEAD bulk data encryption pipelines."
        },
        {
            "name": "Certificate Lifecycle Automation",
            "score": round(lifecycle_score / 0.25 * 100, 1),
            "max": 100,
            "status": "Automated ACME/Vault" if automated_cert_rotation else "Manual / Static Deployment",
            "recommendation": "Implement automated certificate issuance and short validity windows (ACME / HashiCorp Vault)."
        }
    ]

    return {
        "cai_score": total_cai,
        "cai_percentage": int(total_cai * 100),
        "tier": tier,
        "badge_color": badge_color,
        "posture": posture,
        "pillars": pillars,
        "migration_readiness_weeks": max(2, int((1.0 - total_cai) * 24))
    }
