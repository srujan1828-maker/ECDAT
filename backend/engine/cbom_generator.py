import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

def _map_primitive_to_cdx(primitive: str, category: str) -> Dict[str, Any]:
    """Maps internal finding primitive types to CycloneDX 1.6 ECMA-424 crypto properties."""
    p_upper = primitive.upper()

    if "MD5" in p_upper:
        return {
            "primitive": "hash",
            "parameterSetIdentifier": "128",
            "cryptoFunctions": ["digest"],
            "classicalSecurityLevel": 0,
            "nistQuantumSecurityLevel": 0
        }
    elif "SHA-1" in p_upper or "SHA1" in p_upper:
        return {
            "primitive": "hash",
            "parameterSetIdentifier": "160",
            "cryptoFunctions": ["digest"],
            "classicalSecurityLevel": 60,
            "nistQuantumSecurityLevel": 0
        }
    elif "DES" in p_upper and "TRIPLE" not in p_upper and "3DES" not in p_upper:
        return {
            "primitive": "block-cipher",
            "parameterSetIdentifier": "56",
            "cryptoFunctions": ["encrypt", "decrypt"],
            "classicalSecurityLevel": 56,
            "nistQuantumSecurityLevel": 0
        }
    elif "TRIPLE" in p_upper or "3DES" in p_upper:
        return {
            "primitive": "block-cipher",
            "parameterSetIdentifier": "112",
            "cryptoFunctions": ["encrypt", "decrypt"],
            "classicalSecurityLevel": 112,
            "nistQuantumSecurityLevel": 0
        }
    elif "ECB" in p_upper:
        return {
            "primitive": "mode",
            "parameterSetIdentifier": "ECB",
            "cryptoFunctions": ["encrypt", "decrypt"],
            "classicalSecurityLevel": 0,
            "nistQuantumSecurityLevel": 0
        }
    elif "RC4" in p_upper or "ARC4" in p_upper:
        return {
            "primitive": "stream-cipher",
            "parameterSetIdentifier": "128",
            "cryptoFunctions": ["encrypt", "decrypt"],
            "classicalSecurityLevel": 0,
            "nistQuantumSecurityLevel": 0
        }
    elif "RSA" in p_upper:
        key_bits = 2048
        if "1024" in p_upper:
            key_bits = 1024
            classical_sec = 80
        elif "2048" in p_upper:
            classical_sec = 112
        elif "4096" in p_upper:
            classical_sec = 128
        else:
            classical_sec = 112
            
        return {
            "primitive": "public-key-encryption",
            "parameterSetIdentifier": str(key_bits),
            "cryptoFunctions": ["key-agree", "sign", "encrypt", "decrypt"],
            "classicalSecurityLevel": classical_sec,
            "nistQuantumSecurityLevel": 0  # 0 denotes broken by Shor's algorithm
        }
    else:
        return {
            "primitive": "other",
            "parameterSetIdentifier": "N/A",
            "cryptoFunctions": ["unknown"],
            "classicalSecurityLevel": 0,
            "nistQuantumSecurityLevel": 0
        }

def generate_cyclonedx_cbom(
    code_findings: Optional[List[Dict[str, Any]]] = None,
    network_findings: Optional[List[Dict[str, Any]]] = None,
    target_name: str = "ECDAT-Cryptographic-Audit-Target"
) -> Dict[str, Any]:
    """
    Constructs a standards-compliant CycloneDX v1.6 Cryptographic Bill of Materials (CBOM)
    conforming strictly to the ECMA-424 standard.
    
    Guarantees exact schema keys:
      - bomFormat: "CycloneDX"
      - specVersion: "1.6"
      - serialNumber: "urn:uuid:..."
      - version: 1
      - metadata: tools, timestamp, component
      - components: list of cryptographic-asset components
    """
    if code_findings is None:
        code_findings = []
    if network_findings is None:
        network_findings = []

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    bom_serial = f"urn:uuid:{uuid.uuid4()}"

    components = []
    asset_counter = 1

    # 1. Process Code Analysis Cryptographic Sinks
    for finding in code_findings:
        ref_id = f"cbom-asset-code-{asset_counter}"
        asset_counter += 1
        
        algo_props = _map_primitive_to_cdx(
            finding.get("primitive", "Unknown"),
            finding.get("category", "General")
        )

        component_entry = {
            "type": "cryptographic-asset",
            "bom-ref": ref_id,
            "name": finding.get("primitive", "Unknown Cryptographic Primitive"),
            "description": finding.get("issue", "Discovered cryptographic weakness via AST inspection"),
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": algo_props["primitive"],
                    "parameterSetIdentifier": algo_props["parameterSetIdentifier"],
                    "cryptoFunctions": algo_props["cryptoFunctions"],
                    "classicalSecurityLevel": algo_props["classicalSecurityLevel"],
                    "nistQuantumSecurityLevel": algo_props["nistQuantumSecurityLevel"]
                }
            },
            "properties": [
                {"name": "ecdat:sourceType", "value": "static-code-analysis"},
                {"name": "ecdat:lineNumber", "value": str(finding.get("line", 0))},
                {"name": "ecdat:codeSnippet", "value": finding.get("code", "")[:120]},
                {"name": "ecdat:severity", "value": finding.get("severity", "MEDIUM")},
                {"name": "ecdat:recommendation", "value": finding.get("nist_recommendation", "")},
                {"name": "ecdat:quantumRisk", "value": finding.get("quantum_risk", "")}
            ]
        }
        components.append(component_entry)

    # 2. Process Network Probed TLS Endpoints
    for net in network_findings:
        if net.get("status") == "success":
            ref_id = f"cbom-asset-net-{asset_counter}"
            asset_counter += 1

            cipher_name = net.get("cipher_name", "UNKNOWN_CIPHER")
            protocol = net.get("protocol", "TLS")
            secret_bits = net.get("secret_bits", 0)
            hndl_risk = net.get("hndl_risk", "UNKNOWN")

            # TLS Protocol Component
            proto_entry = {
                "type": "cryptographic-asset",
                "bom-ref": f"{ref_id}-protocol",
                "name": protocol,
                "description": f"Negotiated Transport Layer Security protocol for {net.get('target', 'host')}",
                "cryptoProperties": {
                    "assetType": "protocol",
                    "algorithmProperties": {
                        "primitive": "protocol",
                        "parameterSetIdentifier": protocol,
                        "cryptoFunctions": ["key-agree", "authenticate", "encrypt"],
                        "classicalSecurityLevel": 128 if "1.3" in protocol else (112 if "1.2" in protocol else 0),
                        "nistQuantumSecurityLevel": 0
                    }
                },
                "properties": [
                    {"name": "ecdat:sourceType", "value": "network-tls-probe"},
                    {"name": "ecdat:targetEndpoint", "value": net.get("target", "")},
                    {"name": "ecdat:hndlExposure", "value": hndl_risk},
                    {"name": "ecdat:quantumVulnerable", "value": str(net.get("quantum_vulnerable", True))}
                ]
            }
            components.append(proto_entry)

            # Negotiated Cipher Suite Component
            cipher_entry = {
                "type": "cryptographic-asset",
                "bom-ref": f"{ref_id}-cipher",
                "name": cipher_name,
                "description": f"Negotiated cipher suite during live TLS ClientHello probe",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "key-exchange",
                        "parameterSetIdentifier": str(secret_bits),
                        "cryptoFunctions": ["key-agree", "encrypt"],
                        "classicalSecurityLevel": secret_bits,
                        "nistQuantumSecurityLevel": 0  # Quantum vulnerable due to Shor's / Grover's speedup
                    }
                },
                "properties": [
                    {"name": "ecdat:sourceType", "value": "network-tls-probe"},
                    {"name": "ecdat:targetEndpoint", "value": net.get("target", "")},
                    {"name": "ecdat:hndlRationale", "value": net.get("hndl_rationale", "")},
                    {"name": "ecdat:secretBits", "value": str(secret_bits)}
                ]
            }
            components.append(cipher_entry)

            # X.509 Certificate Component if present
            cert = net.get("certificate", {})
            if cert and "subject" in cert:
                cert_entry = {
                    "type": "cryptographic-asset",
                    "bom-ref": f"{ref_id}-cert",
                    "name": "X.509 Certificate",
                    "description": f"Subject: {cert.get('subject', 'N/A')}",
                    "cryptoProperties": {
                        "assetType": "certificate",
                        "algorithmProperties": {
                            "primitive": "signature",
                            "parameterSetIdentifier": cert.get("signature_algorithm", "sha256WithRSAEncryption"),
                            "cryptoFunctions": ["authenticate", "sign"],
                            "classicalSecurityLevel": 112,
                            "nistQuantumSecurityLevel": 0
                        }
                    },
                    "properties": [
                        {"name": "ecdat:issuer", "value": cert.get("issuer", "")},
                        {"name": "ecdat:validFrom", "value": cert.get("valid_from", "")},
                        {"name": "ecdat:validTo", "value": cert.get("valid_to", "")},
                        {"name": "ecdat:daysRemaining", "value": str(cert.get("days_remaining", 0))},
                        {"name": "ecdat:isExpired", "value": str(cert.get("expired", False))}
                    ]
                }
                components.append(cert_entry)

    # Construct the strictly valid CycloneDX v1.6 document
    cbom: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": bom_serial,
        "version": 1,
        "metadata": {
            "timestamp": now_iso,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "author": "National Technical Research Organisation (NTRO) / ECDAT",
                        "name": "Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)",
                        "version": "1.0.0",
                        "description": "Smart India Hackathon SIH26164 Cryptographic Posture Management Platform"
                    }
                ]
            },
            "component": {
                "type": "application",
                "name": target_name,
                "version": "1.0.0",
                "description": "Enterprise Asset evaluated for Cryptographic Compliance, Quantum Risk, and CBOM."
            }
        },
        "components": components
    }

    return cbom
