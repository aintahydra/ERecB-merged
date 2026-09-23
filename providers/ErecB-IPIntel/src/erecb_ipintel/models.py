from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class IPTuple:
    ip: str
    path: str


@dataclass(slots=True)
class ProviderRawResult:
    status: str
    status_code: int | None
    data: dict | None
    error_summary: str | None = None


@dataclass(slots=True)
class NormalizedIntelRecord:
    ip: str
    ipv4: str | None = None
    ipv6: str | None = None
    country_code: str | None = None
    whois: str | None = None
    reverse_dns: list[str] = field(default_factory=list)
    malicious: str | None = None
    related_iocs: list[str] = field(default_factory=list)
    related_actors: list[str] = field(default_factory=list)
    provider_name: str = ""
    provider_result_code: str | None = None
    provider_transaction_id: str | None = None
    raw_response_json: str | None = None
