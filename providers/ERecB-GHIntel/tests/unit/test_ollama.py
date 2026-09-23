import asyncio

import pytest

from ghintel.providers.base import ProviderRequest
from ghintel.providers.ollama import OllamaProvider, OllamaProviderError


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self) -> None:
        return None

    def json(self):
        return self._payload


class FakeClient:
    def __init__(self, responses, calls) -> None:
        self.responses = responses
        self.calls = calls

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None

    async def request(self, method, path, **kwargs):
        self.calls.append((method, path, kwargs))
        return FakeResponse(self.responses.pop(0))


def test_ollama_verifies_model_and_uses_schema_constrained_chat(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        {"models": [{"name": "gpt-oss:120b"}]},
        {
            "message": {"content": '{"summary":"test"}'},
            "prompt_eval_count": 12,
            "eval_count": 5,
        },
    ]
    calls = []
    monkeypatch.setattr(
        "ghintel.providers.ollama.httpx.AsyncClient",
        lambda **kwargs: FakeClient(responses, calls),
    )
    provider = OllamaProvider(endpoint="http://192.168.0.6:11434", model="gpt-oss:120b", timeout_seconds=1)

    assert asyncio.run(provider.verify_model()) == "gpt-oss:120b"
    result = asyncio.run(provider.enrich(ProviderRequest("github.com/example/tool", "source evidence", "hash", 200)))

    assert (result.raw_text, result.input_tokens, result.output_tokens) == ('{"summary":"test"}', 12, 5)
    method, path, kwargs = calls[1]
    assert (method, path) == ("POST", "/api/chat")
    assert kwargs["json"]["stream"] is False
    assert kwargs["json"]["think"] == "low"
    assert kwargs["json"]["options"] == {"temperature": 0}
    assert "tools" not in kwargs["json"]
    assert kwargs["json"]["format"]["type"] == "object"


def test_ollama_counts_utf8_bytes_conservatively() -> None:
    provider = OllamaProvider(endpoint="http://127.0.0.1:11434", model="gpt-oss:120b", timeout_seconds=1)
    assert asyncio.run(provider.count_tokens("가")) >= len("가".encode("utf-8"))


def test_ollama_rejects_missing_usage_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    monkeypatch.setattr(
        "ghintel.providers.ollama.httpx.AsyncClient",
        lambda **kwargs: FakeClient([{"message": {"content": "{}"}}], calls),
    )
    provider = OllamaProvider(endpoint="http://127.0.0.1:11434", model="gpt-oss:120b", timeout_seconds=1, max_retries=0)
    with pytest.raises(OllamaProviderError, match="prompt_eval_count"):
        asyncio.run(provider.enrich(ProviderRequest("github.com/example/tool", "source", "hash", 200)))
