"""Pydantic response schema and exact-source evidence validation."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import LanguageCategory

PROMPT_VERSION = "1"
RESPONSE_SCHEMA_VERSION = "1"


class StrictResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EvidenceQuote(StrictResponse):
    source_id: int
    quote: str = Field(min_length=1, max_length=1000)


class DocumentedPerson(StrictResponse):
    name: str = Field(min_length=1, max_length=200)
    role: Literal["author", "maintainer", "contributor", "other-documented-role"]
    evidence: list[EvidenceQuote] = Field(default_factory=list)


class MotherTongueClaim(StrictResponse):
    category: LanguageCategory
    subject_name: str | None = None
    rationale: str | None = None
    evidence: list[EvidenceQuote] = Field(default_factory=list)


class EnrichmentResponse(StrictResponse):
    summary: str = Field(min_length=1, max_length=2000)
    tool_types: list[str] = Field(default_factory=list, max_length=20)
    capabilities: list[str] = Field(default_factory=list, max_length=30)
    intended_uses: list[str] = Field(default_factory=list, max_length=30)
    searchable_categories: list[str] = Field(default_factory=list, max_length=30)
    documented_people: list[DocumentedPerson] = Field(default_factory=list, max_length=20)
    inferred_mother_tongue: MotherTongueClaim


class EvidenceValidationError(ValueError):
    pass


def validate_response(raw: str, sources: dict[int, str]) -> EnrichmentResponse:
    try:
        response = EnrichmentResponse.model_validate_json(raw)
    except ValidationError as error:
        raise EvidenceValidationError(str(error)) from error
    for quote in _quotes(response):
        source = sources.get(quote.source_id)
        if source is None:
            raise EvidenceValidationError(f"evidence references source {quote.source_id}, which was not requested")
        if quote.quote not in source:
            raise EvidenceValidationError(f"evidence quote does not occur exactly in source {quote.source_id}")
    return response


def quote_locations(response: EnrichmentResponse, sources: dict[int, str]) -> list[tuple[str, EvidenceQuote, int, int]]:
    result: list[tuple[str, EvidenceQuote, int, int]] = []
    for path, quote in _quotes_with_path(response):
        source = sources[quote.source_id]
        offsets = [index for index in range(len(source)) if source.startswith(quote.quote, index)]
        result.append((path, quote, offsets[0], len(offsets)))
    return result


def _quotes(response: EnrichmentResponse) -> list[EvidenceQuote]:
    return [quote for _, quote in _quotes_with_path(response)]


def _quotes_with_path(response: EnrichmentResponse) -> list[tuple[str, EvidenceQuote]]:
    values = [("inferred_mother_tongue", quote) for quote in response.inferred_mother_tongue.evidence]
    for index, person in enumerate(response.documented_people):
        values.extend((f"documented_people[{index}]", quote) for quote in person.evidence)
    return values
