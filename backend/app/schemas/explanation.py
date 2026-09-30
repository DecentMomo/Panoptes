from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ExplanationContent(BaseModel):
    model_config = ConfigDict(extra="ignore")

    plain_explanation: str = Field(min_length=1)
    why_it_matters: str = Field(min_length=1)
    fixed_code: str = Field(min_length=1)
    fix_rationale: str = Field(min_length=1)
    ai_confidence: Literal["high", "medium", "low"]


class ExplanationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    status: Literal["queued", "running", "completed", "failed"]
    failure_reason: Literal["model_unavailable", "timeout", "invalid_response"] | None = None
    ai_generated: bool = True
    model_name: str | None = None
    prompt_version: str | None = None
    plain_explanation: str | None = None
    why_it_matters: str | None = None
    fixed_code: str | None = None
    fix_rationale: str | None = None
    ai_confidence: str | None = None
    latency_ms: int | None = None
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    updated_at: datetime | None = None
