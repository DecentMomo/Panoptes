from pathlib import Path

from app.ingest.validators import assert_within


def read_window(
    root: Path, relative: str, line_start: int, line_end: int, context: int
) -> tuple[str, str, int]:
    """Return (flagged lines, context window, first line number of the window)."""
    path = assert_within(root, root / relative)
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        return "", "", 1
    start = min(max(line_start, 1), len(lines))
    end = min(max(line_end, start), len(lines))
    flagged = "\n".join(lines[start - 1 : end])
    window_start = max(1, start - context)
    window_end = min(len(lines), end + context)
    window = "\n".join(lines[window_start - 1 : window_end])
    return flagged, window, window_start
