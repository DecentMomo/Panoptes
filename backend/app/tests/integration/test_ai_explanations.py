import json
import os
import zipfile
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.ai.ollama_client import OllamaClient, OllamaResult
from app.models.ai_explanation import AIExplanation
from app.models.finding import Finding
from app.models.project import Project
from app.models.scan import Scan
from app.models.user import User
from app.scanners.base import ToolResult
from app.tests.conftest import register_and_login


def _prompt_injection_sample() -> Path:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "samples" / "vulnerable-python" / "prompt_injection.py"
        if candidate.is_file():
            return candidate
    raise FileNotFoundError("samples/vulnerable-python/prompt_injection.py")


def _create_finding(
    session_factory,
    *,
    email: str = "ada@example.com",
    source_tools: list[str] | None = None,
    code: str = "value = eval(user_input)",
    fingerprint: str = "a" * 64,
) -> int:
    db = session_factory()
    user = db.scalar(select(User).where(User.email == email))
    project = Project(owner_id=user.id, name="AI test")
    db.add(project)
    db.flush()
    scan = Scan(
        project_id=project.id,
        status="completed",
        source_type="zip",
        source_name="sample.zip",
        files_scanned=1,
        files_skipped=0,
    )
    db.add(scan)
    db.flush()
    finding = Finding(
        scan_id=scan.id,
        fingerprint=fingerprint,
        source_tools=source_tools or ["bandit"],
        rule_id="B307",
        title="Use of eval",
        description="eval executes text as code",
        severity="medium",
        confidence="high",
        file_path="prompt_injection.py",
        line_start=3,
        line_end=3,
        code_snippet=code,
        snippet_start_line=1,
        cwe_id="CWE-95",
        owasp_category="A05:2025 - Injection",
        status="open",
    )
    db.add(finding)
    db.commit()
    finding_id = finding.id
    db.close()
    return finding_id


class SuccessfulClient:
    calls = 0

    def generate(self, system: str, prompt: str) -> OllamaResult:
        type(self).calls += 1
        return OllamaResult(
            response=json.dumps(
                {
                    "plain_explanation": "eval executes attacker-controlled text as code.",
                    "why_it_matters": "An attacker can run code with the application's access.",
                    "fixed_code": "result = safe_parse(user_input)",
                    "fix_rationale": "Parse expected data instead of executing it.",
                    "ai_confidence": "high",
                    "severity": "info",
                    "status": "false_positive",
                }
            ),
            latency_ms=321,
            prompt_tokens=120,
            completion_tokens=45,
        )


async def test_prompt_injection_cannot_change_finding_authority(
    client, monkeypatch, tmp_path
) -> None:
    monkeypatch.setattr("app.services.scan_orchestrator.work_root", lambda: tmp_path)
    monkeypatch.setattr("app.api.scans.scan_directory", lambda scan_id: tmp_path / str(scan_id))

    def no_findings(root, workdir):
        return ToolResult("", "", 0, 1, False), []

    monkeypatch.setattr("app.services.scan_orchestrator.run_semgrep", no_findings)
    monkeypatch.setattr("app.services.scan_orchestrator.run_gitleaks", no_findings)
    await register_and_login(client, "ada@example.com")
    project = await client.post("/projects", json={"name": "Prompt injection"})
    archive = tmp_path / "prompt-injection.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.write(_prompt_injection_sample(), "prompt_injection.py")
    scan = await client.post(
        f"/projects/{project.json()['id']}/scans",
        files={"file": ("prompt-injection.zip", archive.read_bytes(), "application/zip")},
    )
    findings = (await client.get(f"/scans/{scan.json()['id']}/findings")).json()
    finding_id = next(item["id"] for item in findings if item["file_path"] == "prompt_injection.py")
    before = (await client.get(f"/findings/{finding_id}")).json()
    monkeypatch.setattr("app.ai.explain_service.OllamaClient", SuccessfulClient)

    response = await client.post(f"/findings/{finding_id}/explanation")
    assert response.status_code == 202
    explanation = (await client.get(f"/findings/{finding_id}/explanation")).json()
    assert explanation["status"] == "completed"
    assert explanation["latency_ms"] == 321

    after = (await client.get(f"/findings/{finding_id}")).json()
    for field in ("severity", "status", "cwe_id", "owasp_category"):
        assert after[field] == before[field]


async def test_gitleaks_never_calls_ollama(client, session_factory, monkeypatch) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _create_finding(
        session_factory,
        source_tools=["gitleaks"],
        code="REDACTED",
    )

    class ForbiddenClient:
        def generate(self, system: str, prompt: str) -> OllamaResult:
            raise AssertionError("Gitleaks data reached the LLM")

    monkeypatch.setattr("app.ai.explain_service.OllamaClient", ForbiddenClient)
    response = await client.post(f"/findings/{finding_id}/explanation")
    assert response.status_code == 200
    assert response.json()["ai_generated"] is False
    assert response.json()["status"] == "completed"


async def test_connection_error_is_failed_and_app_stays_available(
    client, session_factory, monkeypatch
) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _create_finding(session_factory)

    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Ollama is down", request=request)

    monkeypatch.setattr(
        "app.ai.explain_service.OllamaClient",
        lambda: OllamaClient(transport=httpx.MockTransport(unavailable)),
    )
    response = await client.post(f"/findings/{finding_id}/explanation")
    assert response.status_code == 202
    state = (await client.get(f"/findings/{finding_id}/explanation")).json()
    assert state["status"] == "failed"
    assert state["failure_reason"] == "model_unavailable"
    finding = (await client.get(f"/findings/{finding_id}")).json()
    assert (await client.get(f"/scans/{finding['scan_id']}")).status_code == 200
    assert (await client.get("/projects")).status_code == 200


async def test_failed_explanation_can_retry_and_complete(
    client, session_factory, monkeypatch
) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _create_finding(session_factory)

    class FailsOnce:
        calls = 0

        def generate(self, system: str, prompt: str) -> OllamaResult:
            self.__class__.calls += 1
            if self.__class__.calls == 1:
                from app.ai.ollama_client import MODEL_UNAVAILABLE, OllamaError

                raise OllamaError(MODEL_UNAVAILABLE)
            return SuccessfulClient().generate(system, prompt)

    monkeypatch.setattr("app.ai.explain_service.OllamaClient", FailsOnce)
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 202
    assert (await client.get(f"/findings/{finding_id}/explanation")).json()["status"] == "failed"
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 202
    assert (await client.get(f"/findings/{finding_id}/explanation")).json()["status"] == "completed"


async def test_invalid_model_json_is_not_stored(client, session_factory, monkeypatch) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _create_finding(session_factory)

    class InvalidClient:
        def generate(self, system: str, prompt: str) -> OllamaResult:
            return OllamaResult("not JSON", 10, 2, 1)

    monkeypatch.setattr("app.ai.explain_service.OllamaClient", InvalidClient)
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 202
    state = (await client.get(f"/findings/{finding_id}/explanation")).json()
    assert state["status"] == "failed"
    assert state["failure_reason"] == "invalid_response"
    assert state["plain_explanation"] is None


async def test_old_confidence_key_is_rejected(client, session_factory, monkeypatch) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _create_finding(session_factory)

    class OldContract:
        def generate(self, system: str, prompt: str) -> OllamaResult:
            return OllamaResult(
                json.dumps(
                    {
                        "plain_explanation": "eval executes text.",
                        "why_it_matters": "An attacker can run code.",
                        "fixed_code": "parse(value)",
                        "fix_rationale": "Do not execute it.",
                        "confidence": "high",
                    }
                ),
                10,
                2,
                1,
            )

    monkeypatch.setattr("app.ai.explain_service.OllamaClient", OldContract)
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 202
    state = (await client.get(f"/findings/{finding_id}/explanation")).json()
    assert state["status"] == "failed"
    assert state["failure_reason"] == "invalid_response"
    assert state["plain_explanation"] is None


async def test_completed_explanation_is_cached_by_prompt_version(
    client, session_factory, monkeypatch
) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _create_finding(session_factory)
    SuccessfulClient.calls = 0
    monkeypatch.setattr("app.ai.explain_service.OllamaClient", SuccessfulClient)

    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 202
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 200
    assert SuccessfulClient.calls == 1

    monkeypatch.setattr("app.ai.explain_service.PROMPT_VERSION", "v2-test")
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 202
    assert SuccessfulClient.calls == 2


async def test_other_user_cannot_access_finding_explanations(
    clients, session_factory, monkeypatch
) -> None:
    alice = clients()
    bob = clients()
    await register_and_login(alice, "alice@example.com")
    await register_and_login(bob, "bob@example.com")
    finding_id = _create_finding(session_factory, email="alice@example.com")
    monkeypatch.setattr("app.ai.explain_service.OllamaClient", SuccessfulClient)

    assert (await bob.get(f"/findings/{finding_id}")).status_code == 404
    assert (await bob.get(f"/findings/{finding_id}/explanation")).status_code == 404
    assert (await bob.post(f"/findings/{finding_id}/explanation")).status_code == 404


async def test_explanation_post_is_rate_limited(client, session_factory, monkeypatch) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _create_finding(session_factory)
    monkeypatch.setattr("app.ai.explain_service.OllamaClient", SuccessfulClient)
    monkeypatch.setattr("app.api.findings.ai_rate_limiter.limit", 2)

    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 202
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 200
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 429


def test_startup_marks_interrupted_explanations_failed(
    client, session_factory, monkeypatch
) -> None:
    db = session_factory()
    row = AIExplanation(
        fingerprint="b" * 64,
        model_name="test-model",
        prompt_version="v1",
        status="running",
    )
    db.add(row)
    db.commit()
    row_id = row.id
    db.close()

    monkeypatch.setattr("app.ai.explain_service.SessionLocal", session_factory)
    from app.ai.explain_service import mark_interrupted_explanations

    mark_interrupted_explanations()
    db = session_factory()
    recovered = db.get(AIExplanation, row_id)
    assert recovered.status == "failed"
    assert recovered.failure_reason == "model_unavailable"
    db.close()


@pytest.mark.skipif(
    os.environ.get("RUN_OLLAMA_TESTS") != "1",
    reason="set RUN_OLLAMA_TESTS=1 only when the configured Ollama model is ready",
)
async def test_live_ollama_explanation(client, session_factory) -> None:
    await register_and_login(client, "ada@example.com")
    finding_id = _create_finding(session_factory)
    assert (await client.post(f"/findings/{finding_id}/explanation")).status_code == 202
    state = (await client.get(f"/findings/{finding_id}/explanation")).json()
    assert state["status"] == "completed"
    assert state["latency_ms"] >= 0
    assert state["prompt_tokens"] >= 0
