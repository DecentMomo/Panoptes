import time
from dataclasses import dataclass

import httpx

from app.core.config import settings

MODEL_UNAVAILABLE = "model_unavailable"
TIMEOUT = "timeout"
INVALID_RESPONSE = "invalid_response"


class OllamaError(Exception):
    def __init__(self, reason: str, latency_ms: int = 0) -> None:
        self.reason = reason
        self.latency_ms = latency_ms
        super().__init__(reason)


@dataclass(frozen=True)
class OllamaResult:
    response: str
    latency_ms: int
    prompt_tokens: int
    completion_tokens: int


class OllamaClient:
    def __init__(self, transport: httpx.BaseTransport | None = None) -> None:
        self._transport = transport

    def generate(self, system: str, prompt: str) -> OllamaResult:
        started = time.perf_counter()
        try:
            with httpx.Client(
                base_url=settings.ollama_base_url,
                timeout=settings.ollama_timeout_seconds,
                transport=self._transport,
            ) as client:
                response = client.post(
                    "/api/generate",
                    json={
                        "model": settings.ollama_model,
                        "system": system,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                        "options": {"temperature": 0},
                    },
                )
                response.raise_for_status()
                payload = response.json()
        except httpx.TimeoutException as exc:
            raise OllamaError(TIMEOUT, _elapsed_ms(started)) from exc
        except (httpx.ConnectError, httpx.HTTPStatusError, httpx.RequestError) as exc:
            raise OllamaError(MODEL_UNAVAILABLE, _elapsed_ms(started)) from exc
        except ValueError as exc:
            raise OllamaError(INVALID_RESPONSE, _elapsed_ms(started)) from exc

        text = payload.get("response") if isinstance(payload, dict) else None
        if not isinstance(text, str) or not text.strip():
            raise OllamaError(INVALID_RESPONSE, _elapsed_ms(started))
        return OllamaResult(
            response=text,
            latency_ms=_elapsed_ms(started),
            prompt_tokens=_count(payload.get("prompt_eval_count")),
            completion_tokens=_count(payload.get("eval_count")),
        )


def _count(value: object) -> int:
    return value if isinstance(value, int) and value >= 0 else 0


def _elapsed_ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
