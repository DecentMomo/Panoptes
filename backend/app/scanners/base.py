import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RawFinding:
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line_start: int
    line_end: int
    cwe_id: str | None
    source_tool: str = "bandit"
    flagged_snippet: str = ""
    code_snippet: str = ""
    snippet_start_line: int = 1
    fingerprint: str = ""
    owasp_category: str | None = None
    source_tools: list[str] = field(default_factory=list)
    # Gitleaks columns are 1-based; the end column is exclusive. Other tools leave these unset.
    secret_start_column: int | None = None
    secret_end_column: int | None = None


@dataclass(frozen=True)
class ToolResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    timed_out: bool
    duplicates_dropped: int = 0


def run_tool(args: list[str], timeout: int, env: dict[str, str] | None = None) -> ToolResult:
    """Run a scanner. `args` is a list so user input can never be a shell string."""
    if isinstance(args, str) or not all(isinstance(arg, str) for arg in args):
        raise TypeError("scanner arguments must be a list of strings")
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            args,
            shell=False,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=env,
        )
    except FileNotFoundError as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        return ToolResult("", str(exc), 127, duration_ms, False)
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        return ToolResult(_as_text(exc.stdout), _as_text(exc.stderr), -1, duration_ms, True)
    duration_ms = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        _as_text(completed.stdout),
        _as_text(completed.stderr),
        completed.returncode,
        duration_ms,
        False,
    )


def relative_path(filename: str, root: Path) -> str:
    path = Path(filename)
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except (ValueError, OSError):
        if not path.is_absolute():
            return path.as_posix().removeprefix("./")
        return path.name


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
