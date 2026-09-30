import zipfile
from pathlib import Path

from app.scanners.base import ToolResult


def sample_dir() -> Path:
    starts = [Path(__file__).resolve(), Path.cwd().resolve()]
    for start in starts:
        for parent in [start, *start.parents]:
            candidate = parent / "samples" / "vulnerable-python"
            if candidate.is_dir():
                return candidate
    raise FileNotFoundError("samples/vulnerable-python")


SAMPLE = sample_dir()


def zip_dir(source: Path, dest: Path) -> None:
    with zipfile.ZipFile(dest, "w") as archive:
        for path in source.iterdir():
            if path.is_file():
                archive.write(path, path.name)


def sample_zip(path: Path) -> None:
    zip_dir(SAMPLE, path)


def empty_scanner(root, workdir):
    return ToolResult("", "", 0, 1, False), []


def stub_other_scanners(monkeypatch) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.run_semgrep", empty_scanner)
    monkeypatch.setattr("app.services.scan_orchestrator.run_gitleaks", empty_scanner)
