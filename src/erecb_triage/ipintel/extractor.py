"""Confined, bounded IPv4/IPv6 extraction from an authorized staged capture."""

from __future__ import annotations

import io
import ipaddress
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

from erecb_triage.config import ip_retriever_settings
from erecb_triage.ipintel.contracts import IpObservation
from erecb_triage.ipintel.spec import (
    IGNORED_IPV4_NETWORKS, MAX_IP_TOKEN_BYTES, MIN_CHUNK_OVERLAP_BYTES,
)
from erecb_triage.processors.base import ProcessorError
from erecb_triage.staging import regular_reader, safe_name


_IGNORED_NETWORKS = tuple(ipaddress.ip_network(network) for network in IGNORED_IPV4_NETWORKS)
# Keep every ASCII letter and digit inside a candidate. Otherwise a value such
# as ``g8.8.8.8z`` could be split at the non-hex letters and yield a false hit.
_TOKEN_BYTES = frozenset(
    b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ:.%[]_-"
)
_ZONE = re.compile(r"[A-Za-z0-9_.-]{1,63}\Z")


class FileTooLarge(OSError):
    pass


class FileChanged(OSError):
    pass


def _metrics() -> dict[str, int]:
    return {
        "ipintel_files_scanned": 0,
        "ipintel_files_skipped": 0,
        "ipintel_observations": 0,
        "ipintel_unique_ips": 0,
        "ipintel_observations_truncated": 0,
        "ipintel_singularities": 0,
    }


@dataclass
class ExtractionResult:
    observations: list[IpObservation] = field(default_factory=list)
    singularities: list[dict] = field(default_factory=list)
    errors: list[ProcessorError] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=_metrics)


def _stat_signature(info: os.stat_result) -> tuple[int, ...]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def _open_directory(root_fd: int, relative: Path):
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("directory path must stay relative to the capture")
    fd = os.dup(root_fd)
    try:
        for part in relative.parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _parse_candidate(token: bytes, delimiter: int | None) -> tuple[str, int] | None:
    if not token:
        return None
    text = token.decode("ascii")
    candidate = text
    bracketed = text.startswith("[")
    if bracketed:
        close = text.find("]")
        if close < 1:
            return None
        candidate, suffix = text[1:close], text[close + 1:]
        if suffix:
            if not suffix.startswith(":") or not _valid_port(suffix[1:]):
                return None
    elif text.count(":") == 1:
        address, port = text.split(":", 1)
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            parsed = None
        if parsed is not None and parsed.version == 4:
            if not _valid_port(port):
                return None
            candidate = address
    elif text.endswith("]"):
        # `]` is also legal boundary punctuation after an unbracketed literal.
        candidate = text[:-1]
    if "%" in candidate:
        if candidate.count("%") != 1 or delimiter == ord("/"):
            return None
        candidate, zone = candidate.split("%", 1)
        if not _ZONE.fullmatch(zone):
            return None
    try:
        parsed = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if bracketed and parsed.version != 6:
        return None
    if parsed.version == 4 and any(parsed in network for network in _IGNORED_NETWORKS):
        return None
    return str(parsed), parsed.version


def _valid_port(port: str) -> bool:
    return port.isascii() and port.isdecimal() and 1 <= int(port) <= 65535


class _TokenStream:
    """A byte-state tokenizer whose carry never exceeds the Phase 1 grammar limit."""

    def __init__(self, carry_limit: int, max_results: int | None = None) -> None:
        if carry_limit <= MAX_IP_TOKEN_BYTES:
            raise ValueError("chunk_overlap_bytes is too small for IP token carry")
        self._carry_limit = carry_limit
        self._max_results = max_results
        self._token = bytearray()
        self._discard = False
        self._found: set[tuple[str, int]] = set()
        self.truncated = False

    def feed(self, chunk: bytes) -> bool:
        """Return true once a distinct-result limit has been exceeded."""
        for byte in chunk:
            if byte in _TOKEN_BYTES:
                if self._discard:
                    continue
                if len(self._token) == MAX_IP_TOKEN_BYTES:
                    self._token.clear()
                    self._discard = True
                else:
                    self._token.append(byte)
                continue
            self._flush(byte)
            if self.truncated:
                return True
        return self.truncated

    def finish(self) -> set[tuple[str, int]]:
        self._flush(None)
        return self._found

    def _flush(self, delimiter: int | None) -> None:
        if not self._discard:
            parsed = _parse_candidate(bytes(self._token), delimiter)
            if parsed is not None:
                if parsed in self._found:
                    pass
                elif self._max_results is not None and len(self._found) >= self._max_results:
                    self.truncated = True
                else:
                    self._found.add(parsed)
        self._token.clear()
        self._discard = False


def extract_stream(reader: BinaryIO, *, chunk_size: int, chunk_overlap: int,
                   max_size: int | None = None) -> tuple[set[tuple[str, int]], int]:
    """Extract from a stream, keeping bounded token carry across every read boundary."""
    found, size, _ = _extract_stream(reader, chunk_size=chunk_size, chunk_overlap=chunk_overlap,
                                     max_size=max_size)
    return found, size


def _extract_stream(reader: BinaryIO, *, chunk_size: int, chunk_overlap: int,
                    max_size: int | None = None, max_results: int | None = None,
                    stop_when_limit_reached: bool = False) -> tuple[set[tuple[str, int]], int, bool]:
    """Internal bounded variant which reports whether the distinct-result cap was reached."""
    if type(chunk_size) is not int or chunk_size < 1:
        raise ValueError("chunk_size must be a positive integer")
    if type(chunk_overlap) is not int or chunk_overlap < MIN_CHUNK_OVERLAP_BYTES:
        raise ValueError("chunk_overlap must meet the configured minimum")
    if max_size is not None and (type(max_size) is not int or max_size < 0):
        raise ValueError("max_size must be a nonnegative integer or null")
    if max_results is not None and (type(max_results) is not int or max_results < 1):
        raise ValueError("max_results must be a positive integer or null")
    scanner = _TokenStream(chunk_overlap, max_results)
    size = 0
    while True:
        amount = chunk_size if max_size is None else min(chunk_size, max_size - size + 1)
        chunk = reader.read(amount)
        if not chunk:
            return scanner.finish(), size, scanner.truncated
        size += len(chunk)
        if max_size is not None and size > max_size:
            raise FileTooLarge("file exceeds max_file_size_bytes")
        limit_reached = scanner.feed(chunk)
        if limit_reached and stop_when_limit_reached:
            return scanner._found, size, True


def extract_bytes(data: bytes, *, chunk_size: int = 1048576, chunk_overlap: int = 256) -> list[tuple[str, int]]:
    """Testable byte-only helper; output is canonical and independent of chunk size."""
    found, size = extract_stream(io.BytesIO(data), chunk_size=chunk_size, chunk_overlap=chunk_overlap)
    assert size == len(data)
    return sorted(found, key=lambda item: (item[1], int(ipaddress.ip_address(item[0]))))


def scan_capture(capture: dict, settings: dict, base_dir: Path) -> ExtractionResult:
    """Scan a caller-authorized staged record; processor authorization is Phase 5 work."""
    settings = ip_retriever_settings(settings)
    if capture.get("type") != "staged_capture":
        raise ValueError("a staged_capture record is required")
    for key in ("staged_path", "capture_name", "source_event_id", "pipeline_run_id"):
        if not isinstance(capture.get(key), str) or not capture[key]:
            raise ValueError(f"staged capture requires {key}")
    root = Path(capture["staged_path"])
    if (not root.is_absolute() or root.is_symlink() or not safe_name(capture["capture_name"])
            or root.name != capture["capture_name"] or root.resolve() != root):
        raise ValueError("invalid staged capture path or identity")
    base_dir = base_dir.resolve()
    result = ExtractionResult()
    capture_limit_reached = False
    per_file_limit_reported = False
    capture_limit_reported = False

    def skip() -> None:
        result.metrics["ipintel_files_skipped"] += 1

    def error(path: Path, exc: BaseException | str, code: str) -> None:
        result.errors.append(ProcessorError(path, str(exc), code))

    def bounded_error(path: Path, message: str, code: str) -> None:
        nonlocal per_file_limit_reported, capture_limit_reported
        if code == "ipintel_per_file_observation_limit":
            if per_file_limit_reported:
                return
            per_file_limit_reported = True
        else:
            if capture_limit_reported:
                return
            capture_limit_reported = True
        error(path, message, code)

    def scan_file(root_fd: int, source: Path, physical: Path, listed: os.stat_result) -> None:
        nonlocal capture_limit_reached
        if capture_limit_reached:
            skip()
            return
        if settings["max_file_size_bytes"] is not None and listed.st_size > settings["max_file_size_bytes"]:
            skip()
            return
        try:
            with _open_directory(root_fd, physical.parent) as parent_fd:
                before = _stat_signature(os.stat(physical.name, dir_fd=parent_fd, follow_symlinks=False))
                if before != _stat_signature(listed):
                    raise FileChanged("file changed after discovery")
                with regular_reader(physical.name, dir_fd=parent_fd) as reader:
                    if _stat_signature(os.fstat(reader.fileno())) != before:
                        raise FileChanged("file changed before reading")
                    found, size, ip_list_singularity = _extract_stream(
                        reader, chunk_size=settings["chunk_size_bytes"],
                        chunk_overlap=settings["chunk_overlap_bytes"],
                        max_size=settings["max_file_size_bytes"],
                        max_results=settings["ip_singularity_threshold"],
                        stop_when_limit_reached=True,
                    )
                    if ((not ip_list_singularity and size != before[2])
                            or _stat_signature(os.fstat(reader.fileno())) != before
                            or _stat_signature(os.stat(physical.name, dir_fd=parent_fd, follow_symlinks=False)) != before
                            or source.resolve(strict=True) != root / physical):
                        raise FileChanged("file or source path changed during scanning")
            result.metrics["ipintel_files_scanned"] += 1
            display = str(source.relative_to(base_dir)) if source.is_relative_to(base_dir) else str(source)
            if ip_list_singularity:
                result.singularities.append({
                    "type": "ip_singularity", "source_path": str(source), "display_path": display,
                    "capture_name": capture["capture_name"], "staged_capture": str(root),
                    "source_event_id": capture["source_event_id"], "pipeline_run_id": capture["pipeline_run_id"],
                    "threshold": settings["ip_singularity_threshold"],
                    "distinct_ips_at_least": settings["ip_singularity_threshold"] + 1,
                })
                return
            for ip, version in sorted(found, key=lambda item: (item[1], int(ipaddress.ip_address(item[0])))):
                if len(result.observations) >= settings["max_observations_per_capture"]:
                    capture_limit_reached = True
                    result.metrics["ipintel_observations_truncated"] = 1
                    bounded_error(root,
                                  f"capture IP observation limit {settings['max_observations_per_capture']} reached; remaining files were not scanned",
                                  "ipintel_observation_limit")
                    break
                result.observations.append(IpObservation(
                    type="ip_observation", ip=ip, ip_version=version, source_path=str(source),
                    display_path=display, capture_name=capture["capture_name"],
                    staged_capture=str(root), source_event_id=capture["source_event_id"],
                    pipeline_run_id=capture["pipeline_run_id"],
                ))
                if len(result.observations) == settings["max_observations_per_capture"]:
                    capture_limit_reached = True
                    result.metrics["ipintel_observations_truncated"] = 1
                    bounded_error(root,
                                  f"capture IP observation limit {settings['max_observations_per_capture']} reached; remaining files were not scanned",
                                  "ipintel_observation_limit")
                    break
        except Exception as exc:
            skip()
            code = ("ipintel_source_changed" if isinstance(exc, FileChanged) else
                    "ipintel_size_limit" if isinstance(exc, FileTooLarge) else "ipintel_read_error")
            error(source, exc, code)

    def walk(root_fd: int) -> None:
        pending = [(Path(), Path(), frozenset())]
        while pending:
            lexical, physical, ancestors = pending.pop()
            source_directory = root / lexical
            children = []
            try:
                with _open_directory(root_fd, physical) as directory_fd:
                    identity_info = os.fstat(directory_fd)
                    identity = (identity_info.st_dev, identity_info.st_ino)
                    if identity in ancestors:
                        error(source_directory, "directory symlink cycle", "ipintel_symlink_cycle")
                        continue
                    lineage = ancestors | {identity}
                    with os.scandir(directory_fd) as entries:
                        ordered = sorted(entries, key=lambda entry: entry.name)
                    for entry in ordered:
                        source, relative = source_directory / entry.name, physical / entry.name
                        try:
                            info = entry.stat(follow_symlinks=False)
                            if stat.S_ISLNK(info.st_mode):
                                if not settings["follow_symlinks"]:
                                    skip()
                                    continue
                                resolved = source.resolve(strict=True)
                                if not resolved.is_relative_to(root):
                                    skip()
                                    error(source, "symlink target is outside the capture", "ipintel_path_outside_capture")
                                    continue
                                relative = resolved.relative_to(root)
                                with _open_directory(root_fd, relative.parent) as parent_fd:
                                    info = os.stat(relative.name or ".", dir_fd=parent_fd, follow_symlinks=False)
                            if stat.S_ISDIR(info.st_mode):
                                if entry.name.startswith(".") and not settings["include_hidden_directories"]:
                                    continue
                                children.append((lexical / entry.name, relative, lineage))
                            elif (not stat.S_ISREG(info.st_mode)
                                  or entry.name.startswith(".") and not settings["include_hidden_files"]):
                                skip()
                            else:
                                scan_file(root_fd, source, relative, info)
                        except (OSError, RuntimeError) as exc:
                            skip()
                            error(source, exc, "ipintel_read_error")
                pending.extend(reversed(children))
            except OSError as exc:
                error(source_directory, exc, "ipintel_scan_error")

    try:
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            identity = os.fstat(root_fd)
            walk(root_fd)
            current = root.stat(follow_symlinks=False)
            if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                raise FileChanged("capture root changed during scanning")
        finally:
            os.close(root_fd)
    except OSError as exc:
        if isinstance(exc, (FileChanged, FileNotFoundError)):
            result.observations.clear()
            result.singularities.clear()
        error(root, exc, "ipintel_scan_error")
    unique = {(item["ip"], item["source_path"]): item for item in result.observations}
    result.observations = sorted(
        unique.values(), key=lambda item: (item["ip_version"], int(ipaddress.ip_address(item["ip"])), item["source_path"]),
    )
    result.singularities.sort(key=lambda item: item["source_path"])
    result.errors.sort(key=lambda issue: (str(issue.path), issue.code, issue.message))
    result.metrics["ipintel_observations"] = len(result.observations)
    result.metrics["ipintel_unique_ips"] = len({item["ip"] for item in result.observations})
    result.metrics["ipintel_singularities"] = len(result.singularities)
    return result
