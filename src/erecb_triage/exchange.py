"""Versioned, indicator-only request bundles for manual machine transfer."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from erecb_triage.ghintel.normalization import normalize_repository


SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_ITEMS = 500_000
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MD5 = re.compile(r"[0-9a-f]{32}\Z")
_BUNDLE_KEYS = {
    "schema_version", "bundle_id", "source_instance_id", "source_sequence",
    "created_at", "selection", "policy_sha256", "files", "ips", "repositories",
    "counts",
}


class BundleError(ValueError):
    """A request bundle is malformed, unsafe, or incompatible."""


def _canonical_uuid(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise BundleError(f"{name} must be a UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise BundleError(f"{name} must be a UUID") from exc
    if str(parsed) != value:
        raise BundleError(f"{name} must be a canonical lowercase UUID")
    return value


def _utc_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BundleError("created_at must be a UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise BundleError("created_at is invalid") from exc
    if parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise BundleError("created_at must be UTC")
    return value


def _pairs_unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BundleError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def validate_bundle(value: Any) -> dict[str, Any]:
    """Validate a complete bundle without mutating it or accepting extra fields."""
    if not isinstance(value, dict) or set(value) != _BUNDLE_KEYS:
        raise BundleError("bundle fields do not match schema version 1")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise BundleError("unsupported bundle schema version")
    _canonical_uuid(value["bundle_id"], "bundle_id")
    _canonical_uuid(value["source_instance_id"], "source_instance_id")
    if type(value["source_sequence"]) is not int or value["source_sequence"] < 1:
        raise BundleError("source_sequence must be positive")
    _utc_timestamp(value["created_at"])
    if not isinstance(value["selection"], str) or value["selection"] not in {"missing", "all"}:
        raise BundleError("selection must be missing or all")
    if not isinstance(value["policy_sha256"], str) or not _SHA256.fullmatch(value["policy_sha256"]):
        raise BundleError("policy_sha256 must be lowercase hexadecimal")
    files, ips, repositories = value["files"], value["ips"], value["repositories"]
    if not all(isinstance(items, list) for items in (files, ips, repositories)):
        raise BundleError("indicator collections must be lists")
    if len(files) + len(ips) + len(repositories) > MAX_ITEMS:
        raise BundleError("too many indicators")
    previous = ""
    for item in files:
        if not isinstance(item, dict) or set(item) != {"sha256", "md5"}:
            raise BundleError("file item must have sha256 and md5 fields")
        sha256, md5 = item["sha256"], item["md5"]
        if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
            raise BundleError("file SHA-256 is invalid")
        if md5 is not None and (not isinstance(md5, str) or not _MD5.fullmatch(md5)):
            raise BundleError("file MD5 is invalid")
        if sha256 <= previous:
            raise BundleError("file items must be sorted and unique")
        previous = sha256
    previous = ""
    for ip in ips:
        if not isinstance(ip, str) or ip <= previous:
            raise BundleError("IPs must be sorted and unique")
        try:
            parsed = ipaddress.ip_address(ip)
            if isinstance(parsed, ipaddress.IPv6Address) and parsed.scope_id is not None:
                raise ValueError("scoped IP")
            if str(parsed) != ip:
                raise ValueError("noncanonical IP")
        except ValueError as exc:
            raise BundleError("IP is invalid or noncanonical") from exc
        previous = ip
    previous = ""
    for item in repositories:
        if not isinstance(item, dict) or set(item) != {"identity_key", "canonical_url"}:
            raise BundleError("repository item fields are invalid")
        key, url = item["identity_key"], item["canonical_url"]
        if not isinstance(key, str) or not isinstance(url, str) or key <= previous:
            raise BundleError("repositories must be sorted and unique")
        identity = normalize_repository(url)
        if identity is None or identity.identity_key != key or identity.canonical_url != url:
            raise BundleError("repository identity is invalid or noncanonical")
        previous = key
    expected_counts = {"files": len(files), "ips": len(ips), "repositories": len(repositories)}
    if (not isinstance(value["counts"], dict) or set(value["counts"]) != set(expected_counts)
            or any(type(value["counts"][key]) is not int for key in expected_counts)
            or value["counts"] != expected_counts):
        raise BundleError("indicator counts do not match")
    return value


def new_bundle(*, source_instance_id: str, source_sequence: int, selection: str,
               policy_sha256: str, files: list[dict], ips: list[str],
               repositories: list[dict], created_at: datetime | None = None) -> dict[str, Any]:
    created = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    value = {
        "schema_version": SCHEMA_VERSION,
        "bundle_id": str(uuid.uuid4()),
        "source_instance_id": source_instance_id,
        "source_sequence": source_sequence,
        "created_at": created.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "selection": selection,
        "policy_sha256": policy_sha256,
        "files": sorted(files, key=lambda item: item["sha256"]),
        "ips": sorted(ips),
        "repositories": sorted(repositories, key=lambda item: item["identity_key"]),
        "counts": {"files": len(files), "ips": len(ips), "repositories": len(repositories)},
    }
    return validate_bundle(value)


def _encode(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def write_bundle(path: Path, value: dict[str, Any]) -> Path:
    """Publish a bundle and its checksum manifest; refuse to overwrite either."""
    validate_bundle(value)
    payload = _encode(value)
    if len(payload) > MAX_BUNDLE_BYTES:
        raise BundleError("bundle exceeds size limit")
    manifest_path = Path(str(path) + ".sha256")
    if path.exists() or path.is_symlink() or manifest_path.exists() or manifest_path.is_symlink():
        raise BundleError("bundle or manifest path already exists")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: list[Path] = []
    try:
        for destination, content in (
            (path, payload),
            (manifest_path, (hashlib.sha256(payload).hexdigest() + "  " + path.name + "\n").encode("ascii")),
        ):
            fd, name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=path.parent)
            temporary.append(Path(name))
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(name, destination)
            except FileExistsError as exc:
                raise BundleError(f"bundle output already exists: {destination}") from exc
            Path(name).unlink()
            temporary.pop()
        return path
    finally:
        for candidate in temporary:
            candidate.unlink(missing_ok=True)


def read_bundle(path: Path) -> dict[str, Any]:
    """Read and verify a bounded, checksummed request bundle."""
    manifest_path = Path(str(path) + ".sha256")
    if path.is_symlink() or manifest_path.is_symlink():
        raise BundleError("bundle paths must not be symlinks")
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise BundleError("bundle exceeds size limit")
    payload = path.read_bytes()
    manifest = manifest_path.read_text(encoding="ascii")
    if manifest != hashlib.sha256(payload).hexdigest() + "  " + path.name + "\n":
        raise BundleError("bundle checksum manifest does not match")
    try:
        value = json.loads(payload, object_pairs_hook=_pairs_unique)
    except BundleError:
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        raise BundleError("bundle JSON is invalid") from exc
    return validate_bundle(value)
