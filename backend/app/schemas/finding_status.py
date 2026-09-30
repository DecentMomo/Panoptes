from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

StatusName = Literal["open", "fixed", "false_positive", "accepted_risk"]


class StatusChangeIn(BaseModel):
    status: StatusName
    reason: str | None = Field(default=None, max_length=1000)


class StatusHistoryOut(BaseModel):
    id: int
    finding_id: int
    user_id: int
    user_email: str
    from_status: str
    to_status: str
    reason: str | None
    created_at: datetime
