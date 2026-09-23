"""Record contracts for DESIGN 04; TypedDict does not perform runtime validation."""

from typing import Literal, TypedDict


MatchType = Literal["sha256", "md5"]
LookupStatus = Literal["hit", "miss", "ambiguous", "unavailable", "error"]
Malicious = Literal["yes", "no", "unknown"]


class HashEvidence(TypedDict):
    sha256_hash: str
    md5_hash: str
    capture_name: str
    staged_capture: str
    source_event_id: str
    pipeline_run_id: str


class FileObservation(HashEvidence):
    type: Literal["file_observation"]
    magic: str | None
    classification_reason: str
    size_bytes: int
    source_path: str
    display_path: str


class FileIntelLookup(HashEvidence):
    type: Literal["file_intel_lookup"]
    source_paths: list[str]
    status: LookupStatus
    error_code: str | None


class FileName(TypedDict):
    file_name: str
    source: str
    first_seen_at: str


class Tag(TypedDict):
    tag: str
    source: str
    first_seen_at: str


class ProviderLookup(TypedDict):
    provider: str
    query_hash: str
    query_hash_type: str
    status: str
    http_status: int | None
    requested_at: str
    completed_at: str | None
    raw_response_path: str | None
    error_message: str | None


class HistoricalObservation(TypedDict):
    file_path: str
    file_name: str
    magic: str
    observed_at: str


class FileIntelHit(HashEvidence):
    type: Literal["file_intel_hit"]
    source_paths: list[str]
    match_type: MatchType
    file_entity_id: int
    db_sha256_hash: str | None
    db_md5_hash: str | None
    magic: str | None
    malicious: Malicious
    created_at: str
    updated_at: str
    file_names: list[FileName]
    tags: list[Tag]
    provider_lookups: list[ProviderLookup]
    historical_observations: list[HistoricalObservation]


class FileIntelAmbiguity(HashEvidence):
    type: Literal["file_intel_ambiguity"]
    source_paths: list[str]
    candidate_file_entity_ids: list[int]
    reason: Literal["multiple_md5_rows", "conflicting_sha256"]


FileIntelRecord = FileObservation | FileIntelLookup | FileIntelHit | FileIntelAmbiguity
