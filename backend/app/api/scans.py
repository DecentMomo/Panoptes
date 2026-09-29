import logging
import shutil
from collections import Counter
from pathlib import Path
from zipfile import BadZipFile, ZipFile

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.projects import get_owned_project
from app.core.config import settings
from app.core.deps import get_current_user, verify_csrf
from app.core.rate_limit import RateLimiter, RateLimitExceeded
from app.db.session import get_db
from app.ingest.zip_handler import NOT_A_ZIP, UnsafeArchiveError, save_upload
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.scanner_run import ScannerRun
from app.models.user import User
from app.schemas.scan import FindingOut, ScanDetailOut, ScannerRunOut, ScanOut
from app.services.scan_orchestrator import run_scan, scan_directory

logger = logging.getLogger("panoptes")

router = APIRouter(tags=["scans"])

scan_rate_limiter = RateLimiter(settings.scan_rate_limit, settings.scan_rate_window_seconds)


def enforce_scan_rate_limit(user: User = Depends(get_current_user)) -> User:
    try:
        scan_rate_limiter.check(user.id)
    except RateLimitExceeded:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many scans. Try again in a minute.",
        ) from None
    return user


def get_owned_scan(db: Session, user: User, scan_id: int) -> Scan:
    """Same idea as get_owned_project: the owner filter is part of the lookup."""
    scan = db.scalar(
        select(Scan)
        .join(Project, Scan.project_id == Project.id)
        .where(Scan.id == scan_id, Project.owner_id == user.id)
    )
    if scan is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found")
    return scan


@router.post(
    "/projects/{project_id}/scans",
    response_model=ScanOut,
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_csrf)],
)
def create_scan(
    project_id: int,
    background: BackgroundTasks,
    file: UploadFile = File(...),
    user: User = Depends(enforce_scan_rate_limit),
    db: Session = Depends(get_db),
) -> Scan:
    project = get_owned_project(db, user, project_id)
    source_name = Path(file.filename or "").name
    if not source_name.lower().endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Upload a .zip archive."
        )

    scan = Scan(
        project_id=project.id,
        status="queued",
        source_type="zip",
        source_name=source_name,
        files_scanned=0,
        files_skipped=0,
    )
    db.add(scan)
    db.flush()
    directory = scan_directory(scan.id)
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / "upload.zip"
    try:
        save_upload(file.file, archive, settings.max_upload_bytes)
        _require_zip(archive)
    except UnsafeArchiveError as exc:
        logger.warning("rejected upload for project %s: %s", project.id, exc.detail)
        db.rollback()
        _remove(directory)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=exc.public_message
        ) from None
    except OSError:
        logger.exception("could not store upload for project %s", project.id)
        db.rollback()
        _remove(directory)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="The archive could not be stored."
        ) from None

    db.commit()
    background.add_task(run_scan, scan.id)
    return scan


@router.get("/projects/{project_id}/scans", response_model=list[ScanOut])
def list_scans(
    project_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Scan]:
    get_owned_project(db, user, project_id)
    return list(
        db.scalars(
            select(Scan).where(Scan.project_id == project_id).order_by(Scan.created_at.desc())
        )
    )


@router.get("/scans/{scan_id}", response_model=ScanDetailOut)
def get_scan(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ScanDetailOut:
    scan = get_owned_scan(db, user, scan_id)
    runs = list(db.scalars(select(ScannerRun).where(ScannerRun.scan_id == scan.id)))
    severities = db.scalars(select(Finding.severity).where(Finding.scan_id == scan.id))
    return ScanDetailOut(
        **ScanOut.model_validate(scan).model_dump(),
        scanner_runs=[ScannerRunOut.model_validate(run) for run in runs],
        severity_counts=dict(Counter(severities)),
    )


@router.get("/scans/{scan_id}/findings", response_model=list[FindingOut])
def list_findings(
    scan_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[Finding]:
    scan = get_owned_scan(db, user, scan_id)
    return list(
        db.scalars(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .order_by(Finding.file_path, Finding.line_start)
        )
    )


def _require_zip(path: Path) -> None:
    try:
        with ZipFile(path) as archive:
            archive.namelist()
    except BadZipFile as exc:
        raise UnsafeArchiveError(NOT_A_ZIP, "bad zip") from exc


def _remove(directory: Path) -> None:
    shutil.rmtree(directory, ignore_errors=True)
