from concurrent.futures import ThreadPoolExecutor
from typing import Protocol

from fastapi import Request
from sqlalchemy.orm import Session, sessionmaker


class ExplanationRunner(Protocol):
    def submit(self, explanation_id: int, finding_id: int) -> None: ...

    def shutdown(self) -> None: ...


class ThreadPoolExplanationRunner:
    def __init__(self, max_workers: int) -> None:
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="ai")

    def submit(self, explanation_id: int, finding_id: int) -> None:
        from app.ai.explain_service import run_explanation

        self._executor.submit(run_explanation, explanation_id, finding_id)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


class InlineExplanationRunner:
    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def submit(self, explanation_id: int, finding_id: int) -> None:
        from app.ai.explain_service import run_explanation

        run_explanation(
            explanation_id,
            finding_id,
            session_factory=self._session_factory,
        )

    def shutdown(self) -> None:
        return None


def get_explanation_runner(request: Request) -> ExplanationRunner:
    return request.app.state.explanation_runner
