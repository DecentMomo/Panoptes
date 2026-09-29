import logging
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.session import SessionLocal
from app.ingest.git_clone import (
    URL_NOT_ALLOWED,
    CloneError,
    RepoUrlError,
    assert_public_host,
    clone_repository,
    sanitize_tree,
    validate_repo_url,
)
from app.ingest.zip_handler import ArchiveLimits, UnsafeArchiveError, extract_zip
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.normalize.cwe_map import normalize_cwe
from app.normalize.dedupe import dedupe
from app.normalize.fingerprint import assign_fingerprints
from app.normalize.owasp_map import owasp_for
from app.normalize.redact import apply_redaction
from app.normalize.snippet import read_window
from app.scanners.bandit_runner import scan as run_bandit
from app.scanners.bandit_runner import version as bandit_version
from app.scanners.base import RawFinding, ToolResult
from app.scanners.gitleaks_runner import scan as run_gitleaks
from app.scanners.gitleaks_runner import version as gitleaks_version
from app.scanners.semgrep_runner import scan as run_semgrep
from app.scanners.semgrep_runner import version as semgrep_version

logger = logging.getLogger("panoptes")

SCAN_FAILED = "Scan failed."
INTERRUPTED = "interrupted by restart"


def _scanners():
    # Looked up on each scan so tests can replace a runner.
    return (
        ("bandit", run_bandit, bandit_version),
        ("semgrep", run_semgrep, semgrep_version),
        ("gitleaks", run_gitleaks, gitleaks_version),
    )


def work_root() -> Path:
    if settings.scan_workdir:
        return Path(settings.scan_workdir)
    return Path(tempfile.gettempdir()) / "panoptes-scans"


def scan_directory(scan_id: int) -> Path:
    return work_root() / str(scan_id)


def mark_interrupted_scans() -> None:
    """A restart drops queued work. Leave no scan stuck in queued or running."""
    db = SessionLocal()
    try:
        stuck = list(db.scalars(select(Scan).where(Scan.status.in_(("queued", "running")))))
        now = datetime.now(UTC)
        for scan in stuck:
            scan.status = "failed"
            scan.error_message = INTERRUPTED
            scan.finished_at = now
            shutil.rmtree(scan_directory(scan.id), ignore_errors=True)
            logger.warning("marked scan %s failed: %s", scan.id, INTERRUPTED)
        db.commit()
    except Exception:
        logger.exception("could not recover interrupted scans")
        db.rollback()
    finally:
        db.close()


def run_scan(scan_id: int, session_factory: sessionmaker[Session] | None = None) -> None:
    factory = session_factory or SessionLocal
    db = factory()
    directory = scan_directory(scan_id)
    try:
        scan = db.get(Scan, scan_id)
        if scan is None or scan.status != "queued":
            return
        scan.status = "running"
        scan.started_at = datetime.now(UTC)
        db.commit()
        _execute(db, scan, directory)
    except Exception:
        logger.exception("scan %s failed", scan_id)
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is not None and scan.status not in {"failed", "completed", "partial"}:
            _fail(db, scan, SCAN_FAILED)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
        db.close()


def _execute(db: Session, scan: Scan, directory: Path) -> None:
    extracted_root = directory / "src"
    limits = ArchiveLimits(settings.max_uncompressed_bytes, settings.max_file_count)
    try:
        files_scanned, files_skipped = _ingest(scan, directory, extracted_root, limits)
    except RepoUrlError as exc:
        logger.warning("scan %s rejected repository: %s", scan.id, exc.detail)
        _fail(db, scan, URL_NOT_ALLOWED)
        return
    except CloneError as exc:
        logger.error("scan %s clone failed: %s", scan.id, exc.detail)
        _fail(db, scan, SCAN_FAILED)
        return
    except UnsafeArchiveError as exc:
        logger.warning("scan %s rejected source: %s", scan.id, exc.detail)
        _fail(db, scan, exc.public_message)
        return

    scan.files_scanned = files_scanned
    scan.files_skipped = files_skipped
    findings, succeeded, duplicates_dropped = _run_scanners(db, scan, extracted_root, directory)
    if succeeded == 0:
        _fail(db, scan, SCAN_FAILED)
        return

    raw = len(findings) + duplicates_dropped
    merges = _prepare(extracted_root, findings)
    rows = [_to_row(scan.id, finding) for finding in findings]
    stored = len(rows)
    logger.info(
        "scan %s findings raw=%d duplicates=%d merged=%d stored=%d",
        scan.id,
        raw,
        duplicates_dropped,
        merges,
        stored,
    )
    if stored != raw - duplicates_dropped - merges:
        logger.error(
            "scan %s finding count mismatch raw=%d duplicates=%d merged=%d stored=%d",
            scan.id,
            raw,
            duplicates_dropped,
            merges,
            stored,
        )
        raise RuntimeError(f"scan {scan.id} lost findings before storing them")
    for row in rows:
        db.add(row)
    scan.status = "completed" if succeeded == len(_scanners()) else "partial"
    scan.finished_at = datetime.now(UTC)
    db.commit()


def _ingest(
    scan: Scan, directory: Path, extracted_root: Path, limits: ArchiveLimits
) -> tuple[int, int]:
    if scan.source_type == "git":
        url, host = validate_repo_url(scan.source_name)
        assert_public_host(host)
        result = clone_repository(
            url, extracted_root, directory / "home", settings.clone_timeout_seconds
        )
        if result.timed_out or result.exit_code != 0:
            detail = "timed out" if result.timed_out else result.stderr[:500]
            raise CloneError(detail or f"git exit {result.exit_code}")
        return sanitize_tree(extracted_root, limits)
    archive = directory / "upload.zip"
    return extract_zip(archive, extracted_root, limits)


def _run_scanners(
    db: Session, scan: Scan, root: Path, workdir: Path
) -> tuple[list[RawFinding], int, int]:
    collected: list[RawFinding] = []
    succeeded = 0
    duplicates_dropped = 0
    for name, runner, tool_version in _scanners():
        result, findings = runner(root, workdir)
        row = ScannerRun(
            scan_id=scan.id,
            tool=name,
            duration_ms=result.duration_ms,
            finding_count=0,
            tool_version=tool_version()[:120],
        )
        status, message = _scanner_status(name, result, findings)
        row.status = status
        row.error_message = message
        if status == "completed":
            row.finding_count = len(findings)
            collected.extend(findings)
            duplicates_dropped += result.duplicates_dropped
            succeeded += 1
        else:
            logger.error("scan %s %s %s", scan.id, name, message)
        db.add(row)
    return collected, succeeded, duplicates_dropped


def _scanner_status(
    name: str, result: ToolResult, findings: list[RawFinding]
) -> tuple[str, str | None]:
    del findings
    if result.timed_out:
        return "timeout", f"{name} timed out"
    if result.exit_code != 0:
        return "failed", f"{name} failed"
    return "completed", None


def _prepare(root: Path, findings: list[RawFinding]) -> int:
    _attach_snippets(root, findings)
    apply_redaction(findings)
    for finding in findings:
        finding.cwe_id = normalize_cwe(finding.cwe_id)
        finding.owasp_category = owasp_for(finding.cwe_id)
        if not finding.source_tools:
            finding.source_tools = [finding.source_tool]
    merged, merges = dedupe(findings)
    findings.clear()
    findings.extend(merged)
    assign_fingerprints(findings)
    return merges


def _attach_snippets(root: Path, findings: list[RawFinding]) -> None:
    for finding in findings:
        if finding.source_tool == "gitleaks":
            continue
        try:
            flagged, window, start = read_window(
                root,
                finding.file_path,
                finding.line_start,
                finding.line_end,
                settings.snippet_context_lines,
            )
        except OSError:
            logger.warning("could not read %s for a snippet", finding.file_path)
            flagged, window, start = "", "", finding.line_start
        finding.flagged_snippet = flagged
        finding.code_snippet = window
        finding.snippet_start_line = start


def _to_row(scan_id: int, finding: RawFinding) -> Finding:
    return Finding(
        scan_id=scan_id,
        fingerprint=finding.fingerprint,
        source_tools=finding.source_tools or [finding.source_tool],
        rule_id=finding.rule_id,
        title=finding.title[:300],
        description=finding.description,
        severity=finding.severity,
        confidence=finding.confidence,
        file_path=finding.file_path[:500],
        line_start=finding.line_start,
        line_end=finding.line_end,
        code_snippet=finding.code_snippet,
        snippet_start_line=finding.snippet_start_line,
        cwe_id=finding.cwe_id,
        owasp_category=finding.owasp_category,
        status="open",
    )


def _fail(db: Session, scan: Scan, message: str) -> None:
    scan.status = "failed"
    scan.error_message = message
    scan.finished_at = datetime.now(UTC)
    db.commit()
