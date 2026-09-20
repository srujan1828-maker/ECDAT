"""ECDAT Command-Line Interface (CLI).

Automated Cryptographic Discovery & Deterministic Auto-Patching Tool.

Usage:
    python -m backend.cli patch --path <dir_or_file> [--apply] [--dry-run] [--no-tests]
    python -m backend.cli scan --path <dir_or_file>
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import List, Optional

# Ensure backend root is on sys.path
_backend_dir = os.path.dirname(os.path.abspath(__file__))
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)

from engine.patch_engine import AutoPatchEngine, MigrationPatch
from engine.source_scan import scan_sources

IGNORE_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".next",
    "target",
    ".pytest_cache",
    ".idea",
    ".vscode",
}

SUPPORTED_EXTENSIONS = {
    ".py": "python",
    ".pyw": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".c": "c_cpp",
    ".cpp": "c_cpp",
    ".cc": "c_cpp",
    ".cxx": "c_cpp",
    ".h": "c_cpp",
    ".hpp": "c_cpp",
}


def discover_files(target_path: str) -> List[tuple[str, str]]:
    """Discovers source files to inspect, returning [(file_path, language)]."""
    abs_path = os.path.abspath(target_path)
    if os.path.isfile(abs_path):
        ext = os.path.splitext(abs_path)[1].lower()
        if ext in SUPPORTED_EXTENSIONS:
            return [(abs_path, SUPPORTED_EXTENSIONS[ext])]
        return []

    discovered = []
    for root, dirs, files in os.walk(abs_path):
        # Exclude ignored directories in-place
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                discovered.append((os.path.join(root, file), SUPPORTED_EXTENSIONS[ext]))
    return discovered


def run_patch_command(args: argparse.Namespace) -> int:
    """Executes the patch command: scanning, generating diffs, testing, and optionally applying."""
    target_path = os.path.abspath(args.path)
    files = discover_files(target_path)

    print(f"\n==================================================================")
    print(f"  ECDAT Cryptographic Auto-Patch Engine")
    print(f"  Target: {target_path}")
    print(f"  Mode: {'APPLY PATCHES (In-place with backups)' if args.apply else 'DRY RUN (Preview diffs only)'}")
    print(f"  Discovered {len(files)} source file(s) to inspect.")
    print(f"==================================================================\n")

    if not files:
        print("No supported source files found to inspect.")
        return 0

    patches_found: List[tuple[str, MigrationPatch]] = []

    for file_path, lang in files:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception as exc:
            print(f"[-] Could not read {file_path}: {exc}")
            continue

        rel_path = os.path.relpath(file_path, target_path if os.path.isdir(target_path) else os.path.dirname(target_path))
        patch = AutoPatchEngine.create_patch(content, rel_path, lang)
        if patch:
            patches_found.append((file_path, patch))

    if not patches_found:
        print("[+] No known weak cryptographic patterns detected. Codebase is clean according to active rules.")
        return 0

    print(f"Found {len(patches_found)} patchable cryptographic weakness(es):\n")

    applied_count = 0
    test_failed_count = 0

    for idx, (file_path, patch) in enumerate(patches_found, 1):
        rel_path = os.path.relpath(file_path)
        print(f"------------------------------------------------------------------")
        print(f"[{idx}/{len(patches_found)}] File: {rel_path}")
        print(f"  Pattern:     {patch.pattern_id}")
        print(f"  Description: {patch.transformation_description}")

        # Run regression test if requested
        if not args.no_tests:
            patch = AutoPatchEngine.run_regression_test(patch)
            print(f"  Test Status: {patch.verification_status.upper()}")
            if patch.verification_status == "failed":
                test_failed_count += 1
                print(f"  Test Output: {patch.test_output}")

        # Show diff
        print("\n  Unified Diff:")
        for line in patch.unified_diff.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                print(f"    \033[92m{line}\033[0m")
            elif line.startswith("-") and not line.startswith("---"):
                print(f"    \033[91m{line}\033[0m")
            else:
                print(f"    {line}")
        print()

        # Apply patch if requested
        if args.apply:
            backup_needed = not args.no_backup
            res = AutoPatchEngine.apply_patch(file_path, patch.patched_code, backup=backup_needed)
            if res["status"] == "applied":
                applied_count += 1
                print(f"  [✓] Successfully patched: {rel_path}")
                if res["backup_created"]:
                    print(f"      Backup saved to:    {res['backup_path']}")
                if res["weakness_eliminated"]:
                    print(f"      Re-scan Status:     WEAKNESS ELIMINATED (0 findings remaining)")
            else:
                print(f"  [✗] Failed to apply patch to: {rel_path}")

    print(f"\n==================================================================")
    print(f"  Summary:")
    print(f"    Total files inspected: {len(files)}")
    print(f"    Weaknesses detected:   {len(patches_found)}")
    if args.apply:
        print(f"    Patches applied:       {applied_count}")
    else:
        print(f"    Patches previewed:     {len(patches_found)} (Use --apply to write changes)")
    if not args.no_tests:
        print(f"    Tests passed:          {len(patches_found) - test_failed_count}/{len(patches_found)}")
    print(f"==================================================================\n")

    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="ecdat",
        description="ECDAT Cryptographic Discovery & Deterministic Remediation CLI"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: patch
    patch_parser = subparsers.add_parser("patch", help="Detect, preview, and apply cryptographic patches.")
    patch_parser.add_argument(
        "--path",
        default=".",
        help="Path to file or directory to inspect (default: current directory)."
    )
    patch_parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply patches directly to files on disk (creates .bak backups by default)."
    )
    patch_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview unified diffs without modifying files (default behavior)."
    )
    patch_parser.add_argument(
        "--no-tests",
        action="store_true",
        help="Skip running synthetic differential regression tests."
    )
    patch_parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Do not create .bak backup files when --apply is used."
    )

    args = parser.parse_args()

    if args.command == "patch":
        sys.exit(run_patch_command(args))


if __name__ == "__main__":
    main()
