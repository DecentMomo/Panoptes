import logging
from datetime import UTC, datetime

from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.ai.ollama_client import INVALID_RESPONSE, OllamaClient, OllamaError
from app.ai.prompts import PROMPT_VERSION, SYSTEM_PROMPT, build_prompt
from app.core.config import settings
from app.db.session import SessionLocal
from app.models.ai_explanation import AIExplanation
from app.models.finding import Finding
from app.schemas.explanation import ExplanationContent, ExplanationOut
from app.services.ai_runner import ExplanationRunner

logger = logging.getLogger("panoptes")


def fixed_gitleaks_explanation() -> ExplanationOut:
    return ExplanationOut(
        status="completed",
        ai_generated=False,
        plain_explanation="A secret scanner found credential-like data at this location.",
        why_it_matters=(
            "Anyone who can read the repository may be able to use the exposed credential."
        ),
        fixed_code=(
            "Remove the value from source control and load it from a secret store or environment."
        ),
        fix_rationale=(
            "Rotate the exposed credential first, then keep only a non-secret "
            "configuration reference."
        ),
        confidence="high",
    )


def request_explanation(
    db: Session,
    finding: Finding,
    runner: ExplanationRunner,
) -> tuple[ExplanationOut, bool]:
    if "gitleaks" in finding.source_tools:
        return fixed_gitleaks_explanation(), False

    key = (
        AIExplanation.fingerprint == finding.fingerprint,
        AIExplanation.model_name == settings.ollama_model,
        AIExplanation.prompt_version == PROMPT_VERSION,
    )
    row = db.scalar(select(AIExplanation).where(*key))
    should_submit = False
    if row is None:
        row = AIExplanation(
            fingerprint=finding.fingerprint,
            model_name=settings.ollama_model,
            prompt_version=PROMPT_VERSION,
            status="queued",
        )
        db.add(row)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            row = db.scalar(select(AIExplanation).where(*key))
            if row is None:
                raise
        else:
            should_submit = True
    elif row.status == "failed":
        _clear_for_retry(row)
        db.commit()
        should_submit = True

    if should_submit:
        runner.submit(row.id, finding.id)
        db.refresh(row)
    return explanation_out(row), should_submit or row.status in {"queued", "running"}


def get_cached_explanation(db: Session, finding: Finding) -> ExplanationOut | None:
    if "gitleaks" in finding.source_tools:
        return fixed_gitleaks_explanation()
    row = db.scalar(
        select(AIExplanation).where(
            AIExplanation.fingerprint == finding.fingerprint,
            AIExplanation.model_name == settings.ollama_model,
            AIExplanation.prompt_version == PROMPT_VERSION,
        )
    )
    return explanation_out(row) if row else None


def run_explanation(
    explanation_id: int,
    finding_id: int,
    session_factory: sessionmaker[Session] | None = None,
) -> None:
    db = (session_factory or SessionLocal)()
    try:
        row = db.get(AIExplanation, explanation_id)
        finding = db.get(Finding, finding_id)
        if row is None or row.status != "queued":
            return
        row.status = "running"
        db.commit()
        if finding is None:
            _fail(row, INVALID_RESPONSE)
            db.commit()
            return

        try:
            result = OllamaClient().generate(SYSTEM_PROMPT, build_prompt(finding))
            row.latency_ms = result.latency_ms
            row.prompt_tokens = result.prompt_tokens
            row.completion_tokens = result.completion_tokens
            content = ExplanationContent.model_validate_json(result.response)
        except OllamaError as exc:
            row.latency_ms = exc.latency_ms
            row.prompt_tokens = 0
            row.completion_tokens = 0
            _fail(row, exc.reason)
            db.commit()
            _log_failed_call(row)
            return
        except ValidationError:
            _fail(row, INVALID_RESPONSE)
            db.commit()
            _log_failed_call(row)
            return

        row.status = "completed"
        row.failure_reason = None
        row.plain_explanation = content.plain_explanation
        row.why_it_matters = content.why_it_matters
        row.fixed_code = content.fixed_code
        row.fix_rationale = content.fix_rationale
        row.ai_confidence = content.confidence
        db.commit()
        logger.info(
            "AI explanation %s completed model=%s latency_ms=%d prompt_tokens=%d "
            "completion_tokens=%d",
            row.id,
            row.model_name,
            row.latency_ms,
            row.prompt_tokens,
            row.completion_tokens,
        )
    except Exception:
        logger.exception("AI explanation %s failed unexpectedly", explanation_id)
        db.rollback()
        row = db.get(AIExplanation, explanation_id)
        if row is not None and row.status != "completed":
            _fail(row, INVALID_RESPONSE)
            db.commit()
    finally:
        db.close()


def mark_interrupted_explanations() -> None:
    db = SessionLocal()
    try:
        result = db.execute(
            update(AIExplanation)
            .where(AIExplanation.status.in_(("queued", "running")))
            .values(
                status="failed",
                failure_reason="model_unavailable",
                updated_at=datetime.now(UTC),
            )
        )
        db.commit()
        if result.rowcount:
            logger.warning("marked %d interrupted AI explanations failed", result.rowcount)
    except Exception:
        logger.exception("could not recover interrupted AI explanations")
        db.rollback()
    finally:
        db.close()


def explanation_out(row: AIExplanation) -> ExplanationOut:
    return ExplanationOut(
        status=row.status,
        failure_reason=row.failure_reason,
        ai_generated=True,
        model_name=row.model_name,
        prompt_version=row.prompt_version,
        plain_explanation=row.plain_explanation,
        why_it_matters=row.why_it_matters,
        fixed_code=row.fixed_code,
        fix_rationale=row.fix_rationale,
        confidence=row.ai_confidence,
        latency_ms=row.latency_ms,
        prompt_tokens=row.prompt_tokens,
        completion_tokens=row.completion_tokens,
        updated_at=row.updated_at,
    )


def _clear_for_retry(row: AIExplanation) -> None:
    row.status = "queued"
    row.failure_reason = None
    row.plain_explanation = None
    row.why_it_matters = None
    row.fixed_code = None
    row.fix_rationale = None
    row.ai_confidence = None
    row.latency_ms = None
    row.prompt_tokens = None
    row.completion_tokens = None


def _fail(row: AIExplanation, reason: str) -> None:
    row.status = "failed"
    row.failure_reason = reason


def _log_failed_call(row: AIExplanation) -> None:
    logger.info(
        "AI explanation %s failed model=%s reason=%s latency_ms=%d prompt_tokens=%d "
        "completion_tokens=%d",
        row.id,
        row.model_name,
        row.failure_reason,
        row.latency_ms or 0,
        row.prompt_tokens or 0,
        row.completion_tokens or 0,
    )
