from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ScanOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    status: str
    source_type: str
    source_name: str
    files_scanned: int
    files_skipped: int
    error_message: str | None
    created_at: datetime
    started_at: datetime | None
    finished_at: datetime | None


class ScannerRunOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    tool: str
    status: str
    duration_ms: int | None
    finding_count: int
    tool_version: str | None
    error_message: str | None


class ScanDetailOut(ScanOut):
    scanner_runs: list[ScannerRunOut]
    severity_counts: dict[str, int]


class GitScanIn(BaseModel):
    url: str = Field(min_length=1, max_length=255)


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    fingerprint: str
    source_tools: list[str]
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    snippet_start_line: int
    cwe_id: str | None
    owasp_category: str | None
    status: str
    status_reason: str | None
    created_at: datetime
