def diff_fingerprints(base: set[str], head: set[str]) -> tuple[set[str], set[str], set[str]]:
    """Fixed vanished, new appeared, still_open stayed. Line numbers are not involved."""
    return base - head, head - base, base & head
