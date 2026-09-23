import asyncio
from types import SimpleNamespace

import pytest

from ghintel.providers.anthropic import AnthropicProvider, AnthropicProviderError
from ghintel.providers.base import ProviderRequest


class FakeModels:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    async def retrieve(self, model: str):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeMessages:
    def __init__(self) -> None:
        self.count_kwargs = None
        self.create_kwargs = None

    async def count_tokens(self, **kwargs):
        self.count_kwargs = kwargs
        return SimpleNamespace(input_tokens=17)

    async def create(self, **kwargs):
        self.create_kwargs = kwargs
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text='{"summary":"test"}')],
            usage=SimpleNamespace(input_tokens=17, output_tokens=9),
        )


class FakeClient:
    def __init__(self, models: FakeModels, messages: FakeMessages) -> None:
        self.models = models
        self.messages = messages


def test_claude_enrichment_counts_tokens_and_requests_schema_json() -> None:
    messages = FakeMessages()
    provider = AnthropicProvider(api_key="test", model="claude-sonnet-4-6", timeout_seconds=1)
    provider._client = lambda: FakeClient(FakeModels([]), messages)  # type: ignore[method-assign]

    assert asyncio.run(provider.count_tokens("source evidence")) == 17
    result = asyncio.run(provider.enrich(ProviderRequest("github.com/example/tool", "source evidence", "hash", 200)))

    assert result.raw_text == '{"summary":"test"}'
    assert (result.input_tokens, result.output_tokens) == (17, 9)
    assert messages.count_kwargs["messages"] == [{"role": "user", "content": "source evidence"}]
    assert "tools" not in messages.create_kwargs
    assert messages.create_kwargs["output_config"]["format"]["type"] == "json_schema"


def test_claude_model_verification_retries_transient_timeout() -> None:
    models = FakeModels([TimeoutError(), SimpleNamespace(id="claude-sonnet-4-6")])
    delays: list[float] = []

    async def sleep(delay: float) -> None:
        delays.append(delay)

    provider = AnthropicProvider(api_key="test", model="claude-sonnet-4-6", timeout_seconds=1, max_retries=1, sleep=sleep)
    provider._client = lambda: FakeClient(models, FakeMessages())  # type: ignore[method-assign]

    assert asyncio.run(provider.verify_model()) == "claude-sonnet-4-6"
    assert models.calls == 2
    assert delays == [1]


def test_claude_model_verification_does_not_retry_non_transient_failure() -> None:
    models = FakeModels([ValueError("invalid model")])
    provider = AnthropicProvider(api_key="test", model="bad", timeout_seconds=1, max_retries=3)
    provider._client = lambda: FakeClient(models, FakeMessages())  # type: ignore[method-assign]

    with pytest.raises(AnthropicProviderError, match="ValueError"):
        asyncio.run(provider.verify_model())
    assert models.calls == 1
