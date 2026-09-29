import subprocess
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolResult:
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    timed_out: bool


def run_tool(args: list[str], timeout: int) -> ToolResult:
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
        )
    except subprocess.TimeoutExpired as exc:
        duration_ms = int((time.perf_counter() - started) * 1000)
        stdout = _as_text(exc.stdout)
        stderr = _as_text(exc.stderr)
        return ToolResult(stdout, stderr, -1, duration_ms, True)
    duration_ms = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        _as_text(completed.stdout),
        _as_text(completed.stderr),
        completed.returncode,
        duration_ms,
        False,
    )


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value
