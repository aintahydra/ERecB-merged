from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FileCandidate:
    path: Path
    name: str
    size_bytes: int


@dataclass(frozen=True)
class ClassificationResult:
    path: Path
    magic: str
    is_executable: bool
    reason: str


@dataclass(frozen=True)
class HashResult:
    sha256_hash: str
    md5_hash: str


@dataclass(frozen=True)
class FileObservation:
    scan_job_id: int
    file_path: Path
    file_name: str
    magic: str
    sha256_hash: str
    md5_hash: str


@dataclass(frozen=True)
class FileForEnrichment:
    id: int
    sha256_hash: str | None
    md5_hash: str | None


@dataclass(frozen=True)
class NormalizedIntel:
    provider_name: str
    provider_status: str
    sha256_hash: str | None
    md5_hash: str | None
    magic: str | None
    malicious: str | None
    tags: tuple[str, ...]
    file_names: tuple[str, ...]
    raw_response_path: str | None
    error_message: str | None


@dataclass
class ScanCounters:
    files_seen: int = 0
    executables_found: int = 0
    error_count: int = 0


@dataclass(frozen=True)
class ScanSummary:
    scan_job_id: int
    status: str
    files_seen: int
    executables_found: int
    error_count: int

