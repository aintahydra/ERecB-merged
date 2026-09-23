from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from yararuler.errors import CacheError, RuleBuildError
from yararuler.models import RejectedRule, RuleEntry, SyncedSource

INCLUDE_RE = re.compile(r'^\s*include\s+["\']([^"\']+)["\']', re.MULTILINE)
MAX_DIAGNOSTIC = 4000


def require_yara() -> Any:
    try:
        import yara
    except ImportError as exc:
        raise CacheError(
            "yara-python is not installed; install the project dependencies first"
        ) from exc
    return yara


def yara_version() -> str:
    return yara_runtime()["yara_version"]


def yara_runtime() -> dict[str, str]:
    """Return the exact libyara and yara-python versions embedded in a cache."""
    yara = require_yara()
    runtime = {
        "yara_version": str(getattr(yara, "YARA_VERSION", "")),
        "yara_python_version": str(getattr(yara, "__version__", "")),
    }
    if not all(runtime.values()):
        raise CacheError("installed yara-python does not expose required runtime version metadata")
    return runtime


def redact_url(value: str) -> str:
    """Keep cache provenance useful without persisting URL credentials."""
    parts = urlsplit(value)
    if not parts.scheme or not parts.netloc:
        return value
    host = parts.hostname or ""
    if parts.port is not None:
        host += f":{parts.port}"
    return urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def namespace_for(source: str, relative_path: str) -> str:
    normalized = re.sub(r"[^A-Za-z0-9_]", "_", f"{source}__{relative_path}")
    short_hash = hashlib.sha256(relative_path.encode("utf-8", "surrogateescape")).hexdigest()[:12]
    return f"ns_{normalized[:160]}__{short_hash}"


def discover_rule_files(source: SyncedSource) -> list[Path]:
    found: list[Path] = []
    for directory, dirnames, filenames in os.walk(source.path, followlinks=False):
        dirnames[:] = sorted(name for name in dirnames if not (Path(directory) / name).is_symlink())
        for filename in sorted(filenames):
            path = Path(directory) / filename
            if path.suffix.lower() in {".yar", ".yara"} and not path.is_symlink():
                found.append(path)
    return found


def _safe_include(include: str, calling_file: Path, root: Path) -> Path:
    requested = Path(include)
    if requested.is_absolute():
        raise RuleBuildError(f"absolute include is forbidden: {include}")
    resolved = (calling_file.parent / requested).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise RuleBuildError(f"include escapes source root: {include}") from exc
    if not resolved.is_file():
        raise RuleBuildError(f"include not found: {include}")
    return resolved


def validate_include_tree(path: Path, root: Path) -> None:
    visited: set[Path] = set()
    active: set[Path] = set()

    def visit(current: Path) -> None:
        current = current.resolve()
        if current in active:
            raise RuleBuildError(f"include cycle detected at {current.relative_to(root)}")
        if current in visited:
            return
        active.add(current)
        try:
            text = current.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise RuleBuildError(f"cannot read rule/include {current}: {exc}") from exc
        for match in INCLUDE_RE.finditer(text):
            visit(_safe_include(match.group(1), current, root))
        active.remove(current)
        visited.add(current)

    visit(path)


def include_callback_for(root: Path):
    root = root.resolve()

    def callback(requested_filename: str, filename: str, namespace: str) -> str:
        del namespace
        calling = Path(filename).resolve() if filename else root
        included = _safe_include(requested_filename, calling, root)
        return included.read_text(encoding="utf-8")

    return callback


def _diagnostic(exc: BaseException) -> str:
    return str(exc).replace("\x00", "")[:MAX_DIAGNOSTIC]


def validate_sources(
    sources: Iterable[SyncedSource],
) -> tuple[list[RuleEntry], list[RejectedRule]]:
    yara = require_yara()
    accepted: list[RuleEntry] = []
    rejected: list[RejectedRule] = []
    for source in sources:
        callback = include_callback_for(source.path)
        for path in discover_rule_files(source):
            relative = path.relative_to(source.path).as_posix()
            try:
                digest = sha256_file(path)
            except OSError as exc:
                digest = ""
                rejected.append(
                    RejectedRule(
                        source.name,
                        source.url,
                        source.commit,
                        relative,
                        path,
                        digest,
                        "read",
                        type(exc).__name__,
                        _diagnostic(exc),
                    )
                )
                continue
            try:
                validate_include_tree(path, source.path)
                yara.compile(
                    filepath=str(path),
                    includes=True,
                    include_callback=callback,
                )
            except Exception as exc:  # yara exposes extension exception classes dynamically
                rejected.append(
                    RejectedRule(
                        source.name,
                        source.url,
                        source.commit,
                        relative,
                        path,
                        digest,
                        "individual_compile",
                        type(exc).__name__,
                        _diagnostic(exc),
                    )
                )
                continue
            accepted.append(
                RuleEntry(
                    source.name,
                    source.url,
                    source.commit,
                    relative,
                    path,
                    digest,
                    namespace_for(source.name, relative),
                )
            )
    return accepted, rejected


def _aggregate_callback(entries: list[RuleEntry]):
    roots = {
        entry.namespace: entry.absolute_path.parents[len(Path(entry.path).parts) - 1]
        for entry in entries
    }

    def callback(requested_filename: str, filename: str, namespace: str) -> str:
        entry_root = roots.get(namespace)
        if entry_root is None:
            raise RuleBuildError(f"unknown namespace during include: {namespace}")
        calling = Path(filename).resolve() if filename else entry_root
        return _safe_include(requested_filename, calling, entry_root).read_text(encoding="utf-8")

    return callback


def compile_aggregate(entries: list[RuleEntry], output: Path) -> None:
    if not entries:
        raise RuleBuildError("no valid YARA rules remain; refusing to publish an empty cache")
    yara = require_yara()
    filepaths = {entry.namespace: str(entry.absolute_path) for entry in entries}
    try:
        compiled = yara.compile(
            filepaths=filepaths,
            includes=True,
            include_callback=_aggregate_callback(entries),
        )
        compiled.save(str(output))
    except Exception as exc:
        raise RuleBuildError(f"aggregate rule compilation failed: {_diagnostic(exc)}") from exc
