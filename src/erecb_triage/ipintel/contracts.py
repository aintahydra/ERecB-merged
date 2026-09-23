"""Record contracts for DESIGN 03; TypedDict does not perform runtime validation."""

from typing import Literal, TypedDict


LookupStatus = Literal["hit", "miss", "unavailable", "error"]
Malicious = Literal["Yes", "No"] | None


class IpEvidence(TypedDict):
    ip: str
    ip_version: Literal[4, 6]
    capture_name: str
    staged_capture: str
    source_event_id: str
    pipeline_run_id: str


class IpObservation(IpEvidence):
    type: Literal["ip_observation"]
    source_path: str
    display_path: str


class IpIntelLookup(IpEvidence):
    type: Literal["ip_intel_lookup"]
    source_paths: list[str]
    status: LookupStatus
    error_code: str | None


class ProviderResult(TypedDict):
    provider_name: str
    provider_status: Literal["success", "not_found", "failed"]
    provider_result_code: str | None
    provider_transaction_id: str | None
    fetched_at: str
    error_summary: str | None


class IpIntelHit(IpEvidence):
    type: Literal["ip_intel_hit"]
    source_paths: list[str]
    ip_entity_id: int
    ipv4: str | None
    ipv6: str | None
    country_code: str | None
    whois: str | None
    malicious: Malicious
    first_seen_local: str
    last_updated_local: str
    reverse_dns: list[str]
    related_iocs: list[str]
    related_actors: list[str]
    provider_results: list[ProviderResult]


IpIntelRecord = IpObservation | IpIntelLookup | IpIntelHit
