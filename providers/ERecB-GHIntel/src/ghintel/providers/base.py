"""Provider-neutral enrichment protocol."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class ProviderRequest:
    repository_key: str
    prompt: str
    source_set_hash: str
    max_output_tokens: int


@dataclass(frozen=True, slots=True)
class ProviderResult:
    raw_text: str
    input_tokens: int
    output_tokens: int


class EnrichmentProvider(Protocol):
    provider_name: str
    model: str

    async def count_tokens(self, prompt: str) -> int: ...

    async def enrich(self, request: ProviderRequest) -> ProviderResult: ...
