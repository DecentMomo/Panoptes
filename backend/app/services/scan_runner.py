from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from fastapi import Request
from sqlalchemy.orm import Session, sessionmaker


class ScanRunner(Protocol):
    def submit(self, scan_id: int) -> None: ...

    def shutdown(self) -> None: ...


class ThreadPoolScanRunner:
    """Runs scans on a pool that is not anyio's, so waiting scans do not hold API threads."""

    def __init__(self, max_workers: int) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan")

    def submit(self, scan_id: int) -> None:
        # Imported here so this module can be loaded without a cycle through the orchestrator.
        from app.services.scan_orchestrator import run_scan

        self._executor.submit(run_scan, scan_id)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


class InlineScanRunner:
    """Runs the scan before submit returns. Tests use this so nothing races the response."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def submit(self, scan_id: int) -> None:
        from app.services.scan_orchestrator import run_scan

        run_scan(scan_id, session_factory=self._session_factory)

    def shutdown(self) -> None:
        return None


def get_scan_runner(request: Request) -> ScanRunner:
    return request.app.state.scan_runner
