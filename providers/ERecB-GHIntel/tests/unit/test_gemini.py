import asyncio
from types import SimpleNamespace

import pytest

from ghintel.providers.gemini import GeminiProvider, GeminiProviderError


class FakeModels:
    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    async def get(self, *, model: str):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeClient:
    def __init__(self, models: FakeModels) -> None:
        self.aio = SimpleNamespace(models=models)
        self.models = SimpleNamespace(get=lambda *, model: asyncio.run(models.get(model=model)))


def test_model_verification_retries_transient_timeout() -> None:
    models = FakeModels([TimeoutError(), SimpleNamespace(name="models/gemini-test")])
    delays: list[float] = []

    async def sleep(delay: float) -> None:
        delays.append(delay)

    provider = GeminiProvider(api_key="test", model="gemini-test", timeout_seconds=1, max_retries=1, sleep=sleep)
    provider._client = lambda: FakeClient(models)  # type: ignore[method-assign]

    assert asyncio.run(provider.verify_model()) == "models/gemini-test"
    assert models.calls == 2
    assert delays == [1]


def test_model_verification_does_not_retry_non_transient_failure() -> None:
    models = FakeModels([ValueError("invalid model")])
    provider = GeminiProvider(api_key="test", model="bad", timeout_seconds=1, max_retries=3)
    provider._client = lambda: FakeClient(models)  # type: ignore[method-assign]

    with pytest.raises(GeminiProviderError, match="ValueError"):
        asyncio.run(provider.verify_model())
    assert models.calls == 1
