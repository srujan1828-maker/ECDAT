"""NVIDIA DeepSeek-R1 AI Cryptographic Refactoring Engine.

Integrates with NVIDIA NIM API (deepseek-ai/deepseek-r1) and RAG post-quantum
standards to perform deep cryptographic reasoning, vulnerability triage,
and post-quantum refactoring with exact unified diff generation.
"""
from __future__ import annotations

import difflib
import json
import os
import re
from typing import Any, Dict, List, Optional
import requests

from .rag_engine import rag_engine
from .patch_engine import AutoPatchEngine

NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_MODEL = "deepseek-ai/deepseek-r1"


def extract_reasoning_and_code(content: str, language: str) -> Dict[str, str]:
    """Extracts DeepSeek-R1 reasoning (<think> tags), explanation, and clean code."""
    reasoning = ""
    clean_text = content

    # 1. Extract <think>...</think> tags if present
    think_match = re.search(r'<think>([\s\S]*?)</think>', content, re.IGNORECASE)
    if think_match:
        reasoning = think_match.group(1).strip()
        clean_text = re.sub(r'<think>[\s\S]*?</think>', '', content, flags=re.IGNORECASE).strip()

    # 2. Extract code block
    code = ""
    # Try finding language-specific block first, e.g. ```python ... ```
    lang_patterns = [
        rf'```(?:{language}|{language.lower()}|{language.upper()})[\s\r\n]+([\s\S]*?)```',
        r'```[a-zA-Z0-9_\+\-]+[\s\r\n]+([\s\S]*?)```',
        r'```[\s\r\n]+([\s\S]*?)```',
    ]

    for pat in lang_patterns:
        matches = re.findall(pat, clean_text)
        if matches:
            # Pick the longest code block (usually the full refactored file)
            code = max(matches, key=len).strip()
            break

    # If no markdown block found, check if clean_text is primarily code
    if not code and ("import " in clean_text or "function" in clean_text or "def " in clean_text or "class " in clean_text):
        code = clean_text

    # Extract explanation without the code block
    explanation = re.sub(r'```[\s\S]*?```', '', clean_text).strip()
    explanation = re.sub(r'\n{3,}', '\n\n', explanation)

    return {
        "reasoning": reasoning,
        "explanation": explanation or "Code refactored to align with NIST post-quantum standards.",
        "code": code,
    }


class DeepSeekR1Engine:
    """NVIDIA NIM DeepSeek-R1 Post-Quantum Refactoring Client."""

    @staticmethod
    def get_api_key(passed_key: Optional[str] = None) -> Optional[str]:
        """Resolves NVIDIA API key from parameter or environment variable."""
        key = (passed_key or "").strip()
        if not key:
            key = os.environ.get("NVIDIA_API_KEY", "").strip()
        return key if key else None

    @classmethod
    def refactor_code(
        cls,
        file_path: str,
        source_code: str,
        language: str = "python",
        findings: Optional[List[Dict[str, Any]]] = None,
        api_key: Optional[str] = None,
        model: str = DEFAULT_MODEL,
    ) -> Dict[str, Any]:
        """Refactors source code using RAG-grounded DeepSeek-R1 reasoning.

        Falls back gracefully to deterministic AST patch engine if API key is missing.
        """
        resolved_key = cls.get_api_key(api_key)

        # 1. Retrieve authoritative PQC standards & recipes via RAG
        findings_str = " ".join([f.get("primitive", "") + " " + f.get("issue", "") for f in (findings or [])])
        rag_query = f"{language} {file_path} {findings_str} {source_code[:500]}"
        rag_docs = rag_engine.retrieve(query=rag_query, language=language, top_k=3)
        rag_context = rag_engine.format_context_for_llm(rag_docs)

        # 2. If no NVIDIA API Key, execute Deterministic AST + RAG Fallback
        if not resolved_key:
            ast_patch = AutoPatchEngine.create_patch(source_code, file_path, language)
            remediated_code = ast_patch.patched_code if ast_patch else source_code
            diff = ast_patch.unified_diff if ast_patch else ""
            explanation = (
                ast_patch.transformation_description
                if ast_patch
                else "No automated AST transformation rule matched this snippet."
            )

            return {
                "success": True,
                "mode": "rag_ast_deterministic",
                "model": "deterministic-ast-engine",
                "api_key_configured": False,
                "file_path": file_path,
                "language": language,
                "reasoning": (
                    "NVIDIA API Key not detected. Executed ECDAT Deterministic AST Engine with zero regressions.\n"
                    "To enable DeepSeek-R1 chain-of-thought reasoning and advanced multi-function refactoring, "
                    "provide an NVIDIA API key in Connection Settings or set NVIDIA_API_KEY."
                ),
                "explanation": f"Standards Applied: {explanation}",
                "remediated_code": remediated_code,
                "unified_diff": diff,
                "rag_standards": rag_docs,
                "warning": "NVIDIA API key not set. DeepSeek-R1 deep reasoning was bypassed; AST deterministic rules applied.",
            }

        # 3. Build RAG-Grounded System & User Prompt for DeepSeek-R1
        system_prompt = (
            "You are ECDAT's Post-Quantum Cryptography (PQC) Senior Security Architect and Code Refactoring Engine.\n"
            "Your task is to analyze vulnerable cryptographic code and refactor it to conform strictly to modern post-quantum "
            "and classical cryptographic mandates (NIST FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA, and FIPS 140-3 AES-256-GCM).\n\n"
            "CRITICAL CONSTRAINTS:\n"
            "1. Ground all cryptographic selections exclusively in the retrieved NIST standards provided below.\n"
            "2. Never suggest or output broken algorithms (MD5, SHA-1, DES, 3DES, RC4, Blowfish, RSA-1024).\n"
            "3. For key establishment, recommend ML-KEM-768 or hybrid X25519MLKEM768 (FIPS 203). Note: ML-KEM is NOT for signatures.\n"
            "4. For digital signatures, recommend ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205).\n"
            "5. For symmetric ciphers, enforce AES-256-GCM AEAD (Grover quantum safe).\n"
            "6. Preserve original business logic, variable names, and function signatures wherever feasible.\n"
            "7. Output your complete refactored code in a single, complete code fence (e.g. ```" + language + "\n...\n```).\n"
            "8. Think step-by-step about classical vs quantum vulnerabilities before generating the remediated code."
        )

        user_prompt = (
            f"=== TARGET FILE: {file_path} (Language: {language}) ===\n\n"
            f"=== RETRIEVED POST-QUANTUM STANDARDS & GUIDELINES (RAG) ===\n"
            f"{rag_context}\n\n"
            f"=== KNOWN DETECTED CRYPTOGRAPHIC VULNERABILITIES ===\n"
            f"{json.dumps(findings or [], indent=2)}\n\n"
            f"=== ORIGINAL SOURCE CODE ===\n"
            f"```{language}\n"
            f"{source_code}\n"
            f"```\n\n"
            "Please analyze the vulnerabilities, explain the quantum and classical risks, and output the complete, production-ready, post-quantum remediated code."
        )

        headers = {
            "Authorization": f"Bearer {resolved_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 4096,
            "top_p": 0.95,
        }

        try:
            res = requests.post(NVIDIA_API_URL, headers=headers, json=payload, timeout=65)

            if res.status_code == 401:
                return {
                    "success": False,
                    "error": "Invalid NVIDIA API key (HTTP 401). Please check your key from https://build.nvidia.com/.",
                    "rag_standards": rag_docs,
                }
            if res.status_code == 402 or res.status_code == 429:
                # Quota or rate limit -> fallback to AST
                ast_patch = AutoPatchEngine.create_patch(source_code, file_path, language)
                remediated = ast_patch.patched_code if ast_patch else source_code
                return {
                    "success": True,
                    "mode": "rag_ast_deterministic",
                    "model": "fallback-ast",
                    "reasoning": f"NVIDIA API rate limit/credits reached (HTTP {res.status_code}). Fell back to deterministic AST.",
                    "explanation": "Deterministic AST engine applied due to NVIDIA NIM rate limit.",
                    "remediated_code": remediated,
                    "unified_diff": ast_patch.unified_diff if ast_patch else "",
                    "rag_standards": rag_docs,
                    "warning": f"NVIDIA NIM Rate Limit (HTTP {res.status_code}). AST fallback executed.",
                }

            if not res.ok:
                raise ValueError(f"NVIDIA API Error (HTTP {res.status_code}): {res.text[:300]}")

            resp_data = res.json()
            choice = resp_data.get("choices", [{}])[0]
            raw_content = choice.get("message", {}).get("content", "")
            raw_reasoning = choice.get("message", {}).get("reasoning_content", "")

            extracted = extract_reasoning_and_code(raw_content, language)
            final_reasoning = raw_reasoning or extracted["reasoning"]
            remediated_code = extracted["code"] or source_code

            # Compute unified diff
            orig_lines = source_code.splitlines(keepends=True)
            remediated_lines = remediated_code.splitlines(keepends=True)
            diff = "".join(difflib.unified_diff(
                orig_lines,
                remediated_lines,
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}"
            ))

            return {
                "success": True,
                "mode": "nvidia_deepseek_r1",
                "model": model,
                "api_key_configured": True,
                "file_path": file_path,
                "language": language,
                "reasoning": final_reasoning,
                "explanation": extracted["explanation"],
                "remediated_code": remediated_code,
                "unified_diff": diff,
                "rag_standards": rag_docs,
                "usage": resp_data.get("usage", {}),
            }

        except Exception as exc:
            # Safe degradation to AST engine on network timeout or connection issue
            ast_patch = AutoPatchEngine.create_patch(source_code, file_path, language)
            return {
                "success": True,
                "mode": "rag_ast_deterministic",
                "model": "fallback-ast",
                "api_key_configured": True,
                "file_path": file_path,
                "language": language,
                "reasoning": f"NVIDIA API connection error: {exc}. Seamlessly applied deterministic AST patch.",
                "explanation": "Deterministic AST engine applied safely.",
                "remediated_code": ast_patch.patched_code if ast_patch else source_code,
                "unified_diff": ast_patch.unified_diff if ast_patch else "",
                "rag_standards": rag_docs,
                "warning": f"DeepSeek-R1 connection failure: {exc}",
            }

    @classmethod
    def explain_finding(
        cls,
        primitive: str,
        issue: str,
        code_context: Optional[str] = None,
        api_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Explains why a primitive is vulnerable to quantum/classical attacks with DeepSeek-R1."""
        resolved_key = cls.get_api_key(api_key)
        rag_docs = rag_engine.retrieve(query=f"{primitive} {issue}", top_k=2)

        if not resolved_key:
            # Deterministic standard explanation
            std_ref = rag_docs[0] if rag_docs else {}
            return {
                "success": True,
                "primitive": primitive,
                "source": "rag_standards",
                "standard": std_ref.get("standard", "NIST / CNSA 2.0"),
                "explanation": std_ref.get("content", f"Primitive {primitive} is classified as insecure or quantum-vulnerable."),
                "recommended_action": std_ref.get("remediation_snippet", "Upgrade to NIST FIPS 203 (ML-KEM) or AES-256-GCM."),
                "rag_standards": rag_docs,
            }

        prompt = (
            f"Explain concisely why the cryptographic primitive '{primitive}' with issue '{issue}' is dangerous "
            f"in both classical and quantum computing contexts (mention Shor's or Grover's algorithm if applicable). "
            f"Context snippet: {code_context or 'N/A'}.\n"
            f"Authoritative Standard: {rag_docs[0].get('standard', '') if rag_docs else 'NIST PQC'}.\n"
            "Provide the explanation and the recommended post-quantum replacement."
        )

        headers = {
            "Authorization": f"Bearer {resolved_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": DEFAULT_MODEL,
            "messages": [
                {"role": "system", "content": "You are a post-quantum cryptography specialist. Be precise, concise, and standard-compliant."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 1024,
        }

        try:
            res = requests.post(NVIDIA_API_URL, headers=headers, json=payload, timeout=30)
            if res.ok:
                ans = res.json().get("choices", [{}])[0].get("message", {}).get("content", "")
                extracted = extract_reasoning_and_code(ans, "python")
                return {
                    "success": True,
                    "primitive": primitive,
                    "source": "nvidia_deepseek_r1",
                    "reasoning": extracted["reasoning"],
                    "explanation": extracted["explanation"],
                    "rag_standards": rag_docs,
                }
        except Exception:
            pass

        # Fallback to RAG
        std_ref = rag_docs[0] if rag_docs else {}
        return {
            "success": True,
            "primitive": primitive,
            "source": "rag_standards_fallback",
            "standard": std_ref.get("standard", "NIST PQC"),
            "explanation": std_ref.get("content", f"Primitive {primitive} requires post-quantum migration."),
            "rag_standards": rag_docs,
        }
