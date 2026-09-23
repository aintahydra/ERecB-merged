from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Candidate:
    sequence: int
    path: Path
    file_path: str


@dataclass(frozen=True)
class ScanErrorRecord:
    path: str
    operation: str
    category: str
    message: str


@dataclass(frozen=True)
class StringMatch:
    identifier: str
    offset: int
    length: int


@dataclass(frozen=True)
class RuleMatch:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict[str, Any]
    strings: list[StringMatch] | None = None


@dataclass(frozen=True)
class FileResult:
    sequence: int
    file_path: str
    absolute_path: str
    sha256: str
    md5: str
    matches: list[RuleMatch]


@dataclass
class ScanMetadata:
    timestamp: str
    completed_at: str
    target_directory: str
    cache_generation: str
    total_files_discovered: int = 0
    total_files_selected: int = 0
    total_files_scanned: int = 0
    total_files_matched: int = 0
    total_matches: int = 0
    total_errors: int = 0
    filters: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanSummary:
    metadata: ScanMetadata
    results: list[FileResult]
    errors: list[ScanErrorRecord]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        for result in data["results"]:
            result.pop("sequence", None)
            for match in result["matches"]:
                if match.get("strings") is None:
                    match.pop("strings", None)
        data["schema_version"] = "1.0"
        return {
            "schema_version": data["schema_version"],
            "scan_metadata": data["metadata"],
            "results": data["results"],
            "errors": data["errors"],
        }


@dataclass(frozen=True)
class SyncedSource:
    name: str
    url: str
    ref: str | None
    commit: str
    path: Path


@dataclass(frozen=True)
class RuleEntry:
    source: str
    source_url: str
    commit: str
    path: str
    absolute_path: Path
    sha256: str
    namespace: str


@dataclass(frozen=True)
class RejectedRule:
    source: str
    source_url: str
    commit: str
    path: str
    absolute_path: Path
    sha256: str
    phase: str
    error_class: str
    diagnostic: str


@dataclass(frozen=True)
class UpdateSummary:
    generation: str
    sources: int
    accepted: int
    quarantined: int
    cache_path: Path
