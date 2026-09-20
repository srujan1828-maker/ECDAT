"""GitHub Ingestion Engine for ECDAT.

Enables direct pulling of public or private repositories, specific branches,
subfolders, or individual source files from GitHub without requiring a local git CLI.
"""
from __future__ import annotations

import io
import os
import re
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import requests

# Source code extensions recognized for cryptographic scanning & patching
SOURCE_CODE_EXTENSIONS = {
    '.py', '.c', '.cpp', '.h', '.hpp', '.cc', '.cxx', '.java', '.go',
    '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.rs', '.rb', '.php',
    '.cs', '.swift', '.kt', '.kts', '.scala', '.m', '.mm',
    '.json', '.yaml', '.yml', '.toml', '.xml', '.sql', '.sh', '.bash',
    '.txt', '.md', '.properties', '.env', '.ini', '.cfg', '.conf'
}

IGNORE_DIRS = {
    'node_modules', '.git', '.svn', '.hg', '__pycache__', '.venv', 'venv',
    '.idea', '.vscode', 'build', 'dist', 'target', '.next', '.cache', '__MACOSX'
}

EXT_TO_LANG = {
    '.py': 'python',
    '.java': 'java',
    '.c': 'c_cpp',
    '.cpp': 'c_cpp',
    '.cc': 'c_cpp',
    '.h': 'c_cpp',
    '.hpp': 'c_cpp',
    '.go': 'golang',
    '.js': 'javascript',
    '.jsx': 'javascript',
    '.ts': 'javascript',
    '.tsx': 'javascript',
    '.mjs': 'javascript',
    '.cjs': 'javascript',
}

MAX_REPO_BYTES = 100 * 1024 * 1024  # 100 MiB archive limit
MAX_FILES = 2500


def parse_github_url(raw_url: str) -> Dict[str, Any]:
    """Parses various GitHub URL formats into owner, repo, ref, subpath, and file metadata."""
    url = raw_url.strip()
    if not url:
        raise ValueError("GitHub URL cannot be empty")

    # Handle git@github.com:owner/repo.git
    ssh_match = re.match(r'^git@github\.com:([^/]+)/([^/]+?)(?:\.git)?$', url)
    if ssh_match:
        return {
            "owner": ssh_match.group(1),
            "repo": ssh_match.group(2),
            "ref": None,
            "subpath": None,
            "is_single_file": False,
        }

    # Clean protocol / prefix
    clean = re.sub(r'^(?:https?://)?(?:www\.)?github\.com/', '', url)
    clean = clean.removesuffix('.git')

    # Match raw.githubusercontent.com
    raw_match = re.match(r'^(?:https?://)?raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)$', url)
    if raw_match:
        return {
            "owner": raw_match.group(1),
            "repo": raw_match.group(2),
            "ref": raw_match.group(3),
            "subpath": raw_match.group(4),
            "is_single_file": True,
        }

    parts = [p for p in clean.split('/') if p]
    if len(parts) < 2:
        # Check if shorthand owner/repo was provided
        shorthand = re.match(r'^([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)$', clean)
        if shorthand:
            return {
                "owner": shorthand.group(1),
                "repo": shorthand.group(2),
                "ref": None,
                "subpath": None,
                "is_single_file": False,
            }
        raise ValueError(f"Invalid GitHub repository URL: {raw_url}")

    owner = parts[0]
    repo = parts[1]
    ref = None
    subpath = None
    is_single_file = False

    if len(parts) >= 4 and parts[2] in ('tree', 'blob'):
        is_single_file = (parts[2] == 'blob')
        ref = parts[3]
        if len(parts) > 4:
            subpath = "/".join(parts[4:])
    elif len(parts) == 3 and parts[2] in ('tree', 'blob'):
        ref = parts[2]

    return {
        "owner": owner,
        "repo": repo,
        "ref": ref,
        "subpath": subpath,
        "is_single_file": is_single_file,
    }


def detect_language(path: str) -> str:
    ext = Path(path).suffix.lower()
    return EXT_TO_LANG.get(ext, 'generic')


class GitHubEngine:
    @staticmethod
    def fetch_repository_files(
        url: str,
        ref: Optional[str] = None,
        subpath: Optional[str] = None,
        token: Optional[str] = None,
        max_files: int = MAX_FILES,
    ) -> Dict[str, Any]:
        """Pulls repository files directly from GitHub using zipball API or raw download."""
        parsed = parse_github_url(url)
        owner = parsed["owner"]
        repo = parsed["repo"]
        target_ref = ref or parsed.get("ref")
        target_subpath = (subpath or parsed.get("subpath") or "").replace("\\", "/").strip("/")

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "ECDAT-PQC-PostQuantum-Scanner/1.0",
        }
        auth_token = token or os.environ.get("GITHUB_TOKEN")
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"

        # 1. Single file direct pull (e.g. blob URL or raw URL)
        if parsed.get("is_single_file") and target_subpath:
            file_ref = target_ref or "main"
            raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{file_ref}/{target_subpath}"
            res = requests.get(raw_url, headers=headers, timeout=25)
            if res.status_code == 404 and not target_ref:
                # Try master branch
                raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/master/{target_subpath}"
                res = requests.get(raw_url, headers=headers, timeout=25)

            if res.status_code in (401, 403):
                raise ValueError(f"GitHub access forbidden (HTTP {res.status_code}). Provide a GitHub token for private repositories.")
            if res.status_code == 404:
                raise ValueError(f"File '{target_subpath}' not found in GitHub repository {owner}/{repo}.")
            if not res.ok:
                raise ValueError(f"GitHub error (HTTP {res.status_code}): {res.text[:200]}")

            content = res.text
            return {
                "repo": f"{owner}/{repo}",
                "ref": file_ref,
                "subpath": target_subpath,
                "is_single_file": True,
                "total_files": 1,
                "total_bytes": len(content.encode('utf-8')),
                "files": [{
                    "path": target_subpath,
                    "content": content,
                    "language": detect_language(target_subpath),
                }],
            }

        # 2. Repository Archive Pull (Streaming Zipball)
        api_ref = f"/{target_ref}" if target_ref else ""
        zip_url = f"https://api.github.com/repos/{owner}/{repo}/zipball{api_ref}"

        res = requests.get(zip_url, headers=headers, allow_redirects=True, stream=True, timeout=45)

        # Fallback to direct public archive if API rate limit or redirection hit
        if res.status_code == 403 and "rate limit" in res.text.lower():
            fallback_ref = target_ref or "main"
            fallback_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{fallback_ref}.zip"
            res = requests.get(fallback_url, headers={"User-Agent": headers["User-Agent"]}, allow_redirects=True, stream=True, timeout=45)

        if res.status_code == 404:
            raise ValueError(f"GitHub repository '{owner}/{repo}' (ref: {target_ref or 'default'}) not found or is private. Provide a GitHub token if private.")
        if res.status_code in (401, 403):
            raise ValueError(f"GitHub access denied (HTTP {res.status_code}). Please supply a GitHub personal access token.")
        if not res.ok:
            raise ValueError(f"Failed to pull repository from GitHub (HTTP {res.status_code}): {res.text[:200]}")

        # Read zipball in memory with size check
        zip_bytes = io.BytesIO()
        total_dl = 0
        for chunk in res.iter_content(chunk_size=65536):
            if chunk:
                total_dl += len(chunk)
                if total_dl > MAX_REPO_BYTES:
                    raise ValueError(f"Repository archive exceeds maximum download limit of {MAX_REPO_BYTES // (1024 * 1024)} MiB.")
                zip_bytes.write(chunk)

        zip_bytes.seek(0)

        files: List[Dict[str, str]] = []
        total_source_bytes = 0

        with zipfile.ZipFile(zip_bytes) as zf:
            infolist = zf.infolist()
            # GitHub zipballs prefix all entries with '{owner}-{repo}-{commit_sha}/'
            for info in infolist:
                if info.is_dir():
                    continue

                raw_path = info.filename.replace('\\', '/').lstrip('/')
                parts = raw_path.split('/')
                # Strip the top-level GitHub archive root folder
                if len(parts) <= 1:
                    continue
                rel_path = "/".join(parts[1:])

                # Filter subpath if specified
                if target_subpath:
                    if not (rel_path == target_subpath or rel_path.startswith(target_subpath + '/')):
                        continue

                # Directory exclusions
                path_segments = rel_path.split('/')
                if any(seg in IGNORE_DIRS or seg.startswith('.') for seg in path_segments[:-1]):
                    continue

                # Extension filter
                ext = Path(rel_path).suffix.lower()
                if ext not in SOURCE_CODE_EXTENSIONS and not rel_path.lower().endswith(('.json', '.yml', '.yaml', '.xml')):
                    continue

                # File size limits
                if info.file_size > 5 * 1024 * 1024:  # Skip files > 5MB
                    continue

                with zf.open(info) as stream:
                    content_raw = stream.read(info.file_size)
                    try:
                        content_str = content_raw.decode('utf-8-sig')
                    except UnicodeDecodeError:
                        content_str = content_raw.decode('latin-1', errors='replace')

                total_source_bytes += len(content_raw)
                files.append({
                    "path": rel_path,
                    "content": content_str,
                    "language": detect_language(rel_path),
                })

                if len(files) >= max_files:
                    break

        if not files:
            raise ValueError(f"No valid source code files found in '{owner}/{repo}'" + (f" matching subpath '{target_subpath}'" if target_subpath else "") + ".")

        return {
            "repo": f"{owner}/{repo}",
            "ref": target_ref or "default",
            "subpath": target_subpath,
            "is_single_file": False,
            "total_files": len(files),
            "total_bytes": total_source_bytes,
            "files": files,
        }
