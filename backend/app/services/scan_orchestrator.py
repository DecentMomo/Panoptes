import logging
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import settings
from app.db.session import SessionLocal
from app.ingest.zip_handler import ArchiveLimits, UnsafeArchiveError, extract_zip
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.normalize.fingerprint import assign_fingerprints
from app.normalize.snippet import read_window
from app.scanners.bandit_runner import RawFinding
from app.scanners.bandit_runner import scan as run_bandit

logger = logging.getLogger("panoptes")

SCAN_FAILED = "Scan failed."
INTERRUPTED = "interrupted by restart"


def work_root() -> Path:
    if settings.scan_workdir:
        return Path(settings.scan_workdir)
    return Path(tempfile.gettempdir()) / "panoptes-scans"


def scan_directory(scan_id: int) -> Path:
    return work_root() / str(scan_id)


def mark_interrupted_scans() -> None:
    """A restart kills BackgroundTasks. Leave no scan stuck in queued or running."""
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
        if scan is not None and scan.status != "failed":
            _fail(db, scan, SCAN_FAILED)
    finally:
        shutil.rmtree(directory, ignore_errors=True)
        db.close()


def _execute(db: Session, scan: Scan, directory: Path) -> None:
    archive = directory / "upload.zip"
    extracted_root = directory / "src"
    limits = ArchiveLimits(settings.max_uncompressed_bytes, settings.max_file_count)
    try:
        files_scanned, files_skipped = extract_zip(archive, extracted_root, limits)
    except UnsafeArchiveError as exc:
        logger.warning("scan %s rejected archive: %s", scan.id, exc.detail)
        _fail(db, scan, exc.public_message)
        return

    scan.files_scanned = files_scanned
    scan.files_skipped = files_skipped
    result, findings = run_bandit(extracted_root)
    scanner_run = ScannerRun(
        scan_id=scan.id,
        tool="bandit",
        duration_ms=result.duration_ms,
        finding_count=0,
    )
    if result.timed_out:
        logger.error("scan %s bandit timed out after %sms", scan.id, result.duration_ms)
        scanner_run.status = "timeout"
        scanner_run.error_message = "Bandit timed out"
        db.add(scanner_run)
        _fail(db, scan, SCAN_FAILED)
        return
    if result.exit_code != 0:
        logger.error(
            "scan %s bandit exited %s: %s", scan.id, result.exit_code, result.stderr[:2000]
        )
        scanner_run.status = "failed"
        scanner_run.error_message = "Bandit failed"
        db.add(scanner_run)
        _fail(db, scan, SCAN_FAILED)
        return

    _attach_snippets(extracted_root, findings)
    assign_fingerprints(findings)
    for finding in findings:
        db.add(_to_row(scan.id, finding))
    scanner_run.status = "completed"
    scanner_run.finding_count = len(findings)
    db.add(scanner_run)
    scan.status = "completed"
    scan.finished_at = datetime.now(UTC)
    db.commit()


def _attach_snippets(root: Path, findings: list[RawFinding]) -> None:
    for finding in findings:
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
        source_tools=[finding.source_tool],
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
        owasp_category=None,
        status="open",
    )


def _fail(db: Session, scan: Scan, message: str) -> None:
    scan.status = "failed"
    scan.error_message = message
    scan.finished_at = datetime.now(UTC)
    db.commit()
