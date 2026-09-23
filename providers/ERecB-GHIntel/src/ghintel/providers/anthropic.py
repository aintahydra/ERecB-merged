"""Claude adapter isolated from the rest of the application."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from ..evidence import EnrichmentResponse
from .base import ProviderRequest, ProviderResult
from .gemini import SYSTEM_INSTRUCTION


class AnthropicProviderError(RuntimeError):
    """An Anthropic SDK operation could not complete within its configured policy."""


class AnthropicProvider:
    """Bounded, schema-constrained Claude enrichment with no tools or file access."""

    provider_name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        timeout_seconds: int,
        max_retries: int = 3,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.model = model
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self._api_key = api_key
        self._sleep = sleep

    async def verify_model(self) -> str:
        """Confirm account access to the configured model without uploading sources."""
        response = await self._run(lambda: self._client().models.retrieve(self.model))
        model_id = getattr(response, "id", None)
        if not isinstance(model_id, str) or not model_id:
            raise AnthropicProviderError("configured model lookup returned no model ID")
        return model_id

    async def count_tokens(self, prompt: str) -> int:
        response = await self._run(
            lambda: self._client().messages.count_tokens(
                model=self.model,
                system=SYSTEM_INSTRUCTION,
                messages=_messages(prompt),
            )
        )
        return int(getattr(response, "input_tokens", 0) or 0)

    async def enrich(self, request: ProviderRequest) -> ProviderResult:
        response = await self._run(
            lambda: self._client().messages.create(
                model=self.model,
                system=SYSTEM_INSTRUCTION,
                messages=_messages(request.prompt),
                max_tokens=request.max_output_tokens,
                temperature=0,
                output_config={
                    "format": {
                        "type": "json_schema",
                        "schema": EnrichmentResponse.model_json_schema(),
                    }
                },
            )
        )
        raw_text = next(
            (
                block.text
                for block in getattr(response, "content", ())
                if getattr(block, "type", None) == "text" and isinstance(getattr(block, "text", None), str)
            ),
            "",
        )
        if not raw_text:
            raise AnthropicProviderError("Claude response contained no text block")
        usage = getattr(response, "usage", None)
        return ProviderResult(
            raw_text=raw_text,
            input_tokens=int(getattr(usage, "input_tokens", 0) or 0),
            output_tokens=int(getattr(usage, "output_tokens", 0) or 0),
        )

    async def _run(self, operation: Callable[[], Awaitable[Any]]) -> Any:
        for attempt in range(self.max_retries + 1):
            try:
                return await asyncio.wait_for(operation(), timeout=self.timeout_seconds)
            except Exception as error:
                if attempt >= self.max_retries or not _retryable(error):
                    raise AnthropicProviderError(f"Anthropic request failed: {type(error).__name__}") from error
                await self._sleep(min(2**attempt, 30))
        raise AssertionError("unreachable")

    def _client(self):
        from anthropic import AsyncAnthropic

        return AsyncAnthropic(api_key=self._api_key, default_headers={"Accept-Encoding": "gzip, deflate"})


def _messages(prompt: str) -> list[dict[str, str]]:
    return [{"role": "user", "content": prompt}]


def _retryable(error: Exception) -> bool:
    if isinstance(error, (TimeoutError, OSError)):
        return True
    status = getattr(error, "status_code", getattr(error, "status", getattr(error, "code", None)))
    return isinstance(status, int) and status in {408, 429, 500, 502, 503, 504}
