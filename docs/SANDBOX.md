# ECDAT V4 — Sandbox & Execution Isolation Engine

## 1. Overview & Threat Model

ECDAT processes untrusted third-party source code, binary archives, and remote network endpoints. A compromised or hostile target must never compromise the host server or backend pipeline.

### Threat Scenarios Mitigated
1. **Malicious Payloads & Zip Bombs**: Decompression bombs designed to exhaust disk or memory during archive extraction.
2. **Infinite Loops & Hangs**: External tools or malformed parsers getting stuck in unbounded CPU loops.
3. **Log & Buffer Flooding**: Subprocesses emitting gigabytes of output to crash the backend or exhaust database storage.
4. **Filesystem Pollution**: Scanners writing temporary artifacts to host root or leaking files across projects.

---

## 2. Sandbox Configuration (`SandboxConfig`)

```python
@dataclass
class SandboxConfig:
    timeout_seconds: float = 30.0
    max_memory_mb: int = 512
    max_output_bytes: int = 1_048_576  # 1 MB
    max_output_lines: int = 10_000
    allow_network: bool = False
    read_only_root: bool = True
```

---

## 3. Workspace Isolation (`run_isolated`)

Every isolated execution runs inside an ephemeral, dedicated directory context:

```python
with sandbox.run_isolated() as workspace_dir:
    # 1. Ephemeral workspace provisioned: e.g. /tmp/ecdat_sandbox_xyz
    # 2. Scanner writes intermediate analysis or temp files
    # 3. Context manager automatically purges workspace upon exit
```

- Guaranteed cleanup on normal exit or exception.
- Completely isolated from host system working directories.

---

## 4. Resource Constraints & Boundary Enforcement

### 1. Bounded Timeouts
Commands exceeding `timeout_seconds` (default: 30s) are forcefully terminated via `proc.kill()` and tagged with `SandboxStatus.TIMEOUT`.

### 2. Output Truncation
Process stdout and stderr streams are continuously metered:
- If stdout exceeds `max_output_bytes` (1 MB) or `max_output_lines` (10,000 lines), streams are truncated with an explicit warning banner:
  `"... [OUTPUT TRUNCATED BY ECDAT SANDBOX]"`
- Prevents memory exhaustion attacks via chatty subprocesses.

### 3. Subprocess Execution Safety
- Commands are executed as argument lists (`list[str]`) with `shell=False` to prevent shell injection.
- Environment variables are filtered to prevent inheriting host API tokens or secrets.
