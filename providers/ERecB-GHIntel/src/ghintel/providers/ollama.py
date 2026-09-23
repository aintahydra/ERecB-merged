"""Local Ollama adapter using its native schema-constrained chat API."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from ..evidence import EnrichmentResponse
from .base import ProviderRequest, ProviderResult
from .gemini import SYSTEM_INSTRUCTION


class OllamaProviderError(RuntimeError):
    """A local Ollama API operation could not complete within its configured policy."""


class OllamaProvider:
    """Use a user-controlled Ollama endpoint without credentials, tools, or cloud calls."""

    provider_name = "ollama"

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        timeout_seconds: int,
        max_retries: int = 1,
        thinking: str = "low",
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.thinking = thinking
        self._sleep = sleep

    async def verify_model(self) -> str:
        """Confirm that the configured local model is present without sending prompts."""
        payload = await self._request("GET", "/api/tags")
        models = payload.get("models")
        if not isinstance(models, list):
            raise OllamaProviderError("Ollama model listing is malformed")
        for item in models:
            if isinstance(item, dict) and item.get("name") == self.model:
                return self.model
        raise OllamaProviderError("configured Ollama model is unavailable")

    async def count_tokens(self, prompt: str) -> int:
        """Reserve conservatively: one input token per UTF-8 byte is a safe upper bound."""
        return max(1, len((SYSTEM_INSTRUCTION + _user_content(prompt)).encode("utf-8")))

    async def enrich(self, request: ProviderRequest) -> ProviderResult:
        payload = await self._request(
            "POST",
            "/api/chat",
            json={
                "model": self.model,
                "messages": [
                    {"role": "system", "content": SYSTEM_INSTRUCTION},
                    {"role": "user", "content": _user_content(request.prompt)},
                ],
                "stream": False,
                "think": self.thinking,
                "options": {"temperature": 0},
                "format": EnrichmentResponse.model_json_schema(),
            },
        )
        message = payload.get("message")
        raw_text = message.get("content") if isinstance(message, dict) else None
        if not isinstance(raw_text, str) or not raw_text:
            raise OllamaProviderError("Ollama response contained no message content")
        return ProviderResult(
            raw_text=raw_text,
            input_tokens=_usage_count(payload, "prompt_eval_count"),
            output_tokens=_usage_count(payload, "eval_count"),
        )

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        for attempt in range(self.max_retries + 1):
            try:
                async with httpx.AsyncClient(base_url=self.endpoint, timeout=self.timeout_seconds) as client:
                    response = await client.request(method, path, **kwargs)
                    response.raise_for_status()
                    payload = response.json()
                if not isinstance(payload, dict):
                    raise OllamaProviderError("Ollama response is not a JSON object")
                return payload
            except Exception as error:
                if isinstance(error, OllamaProviderError) or attempt >= self.max_retries or not _retryable(error):
                    if isinstance(error, OllamaProviderError):
                        raise
                    raise OllamaProviderError(f"Ollama request failed: {type(error).__name__}") from error
                await self._sleep(min(2**attempt, 30))
        raise AssertionError("unreachable")


def _user_content(prompt: str) -> str:
    schema = json.dumps(EnrichmentResponse.model_json_schema(), separators=(",", ":"), ensure_ascii=False)
    return prompt + "\n\nReturn only a JSON object matching this trusted response schema exactly; do not emit prose or citation markup outside JSON. For inferred_mother_tongue, use Unknown with null subject_name and empty evidence unless a documented person has exact supplied-source evidence.\n<response-schema>\n" + schema + "\n</response-schema>"


def _usage_count(payload: dict[str, Any], field: str) -> int:
    value = payload.get(field)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OllamaProviderError(f"Ollama response is missing a valid {field}")
    return value


def _retryable(error: Exception) -> bool:
    if isinstance(error, (httpx.TimeoutException, httpx.NetworkError, OSError)):
        return True
    if isinstance(error, httpx.HTTPStatusError):
        return error.response.status_code in {408, 429, 500, 502, 503, 504}
    return False
