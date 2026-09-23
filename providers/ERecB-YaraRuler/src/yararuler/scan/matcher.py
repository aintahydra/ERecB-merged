from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from yararuler.models import (
    Candidate,
    FileResult,
    RuleMatch,
    ScanErrorRecord,
    StringMatch,
)
from yararuler.rules.compiler import require_yara
from yararuler.scan.hashing import file_hashes

MAX_STRING_INSTANCES_PER_RULE = 10_000
_WORKER_RULES: Any = None


@dataclass(frozen=True)
class MatchOutcome:
    sequence: int
    result: FileResult | None = None
    error: ScanErrorRecord | None = None


def initialize_worker(cache_path: str) -> None:
    global _WORKER_RULES
    _WORKER_RULES = require_yara().load(cache_path)


def _json_scalar(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _string_matches(raw_strings: Any) -> list[StringMatch]:
    normalized: list[StringMatch] = []
    for item in raw_strings:
        if isinstance(item, tuple) and len(item) >= 3:
            offset, identifier, data = item[:3]
            normalized.append(StringMatch(str(identifier), int(offset), len(data)))
            continue
        identifier = str(getattr(item, "identifier", ""))
        for instance in getattr(item, "instances", ()):
            data = getattr(instance, "matched_data", b"")
            length = getattr(instance, "matched_length", len(data))
            normalized.append(
                StringMatch(identifier, int(getattr(instance, "offset", 0)), int(length))
            )
            if len(normalized) >= MAX_STRING_INSTANCES_PER_RULE:
                break
        if len(normalized) >= MAX_STRING_INSTANCES_PER_RULE:
            break
    return sorted(normalized, key=lambda item: (item.offset, item.identifier))


def _normalize_matches(matches: Any, include_strings: bool) -> list[RuleMatch]:
    normalized: list[RuleMatch] = []
    for match in matches:
        normalized.append(
            RuleMatch(
                rule=str(match.rule),
                namespace=str(match.namespace),
                tags=sorted(str(tag) for tag in match.tags),
                meta={str(key): _json_scalar(value) for key, value in match.meta.items()},
                strings=_string_matches(match.strings) if include_strings else None,
            )
        )
    return sorted(normalized, key=lambda item: (item.namespace, item.rule))


def _identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)


def match_candidate(
    rules: Any,
    candidate: Candidate,
    timeout_seconds: int,
    include_strings: bool,
) -> MatchOutcome:
    try:
        before = candidate.path.stat()
        raw_matches = rules.match(filepath=str(candidate.path), timeout=timeout_seconds)
        if not raw_matches:
            return MatchOutcome(candidate.sequence)
        sha256, md5 = file_hashes(candidate.path)
        after = candidate.path.stat()
        if _identity(before) != _identity(after):
            return MatchOutcome(
                candidate.sequence,
                error=ScanErrorRecord(
                    candidate.file_path,
                    "scan",
                    "file_changed_during_scan",
                    "file identity, size, or modification time changed during scan",
                ),
            )
        result = FileResult(
            sequence=candidate.sequence,
            file_path=candidate.file_path,
            absolute_path=str(candidate.path),
            sha256=sha256,
            md5=md5,
            matches=_normalize_matches(raw_matches, include_strings),
        )
        return MatchOutcome(candidate.sequence, result=result)
    except Exception as exc:  # worker must turn dynamic yara and I/O errors into data
        category = "scan_timeout" if type(exc).__name__ == "TimeoutError" else type(exc).__name__
        return MatchOutcome(
            candidate.sequence,
            error=ScanErrorRecord(
                candidate.file_path,
                "scan",
                category,
                str(exc).replace("\x00", "")[:1000],
            ),
        )


def worker_scan(payload: tuple[Candidate, int, bool]) -> MatchOutcome:
    candidate, timeout_seconds, include_strings = payload
    if _WORKER_RULES is None:
        return MatchOutcome(
            candidate.sequence,
            error=ScanErrorRecord(
                candidate.file_path,
                "scan",
                "worker_not_initialized",
                "worker cache is unavailable",
            ),
        )
    return match_candidate(_WORKER_RULES, candidate, timeout_seconds, include_strings)
