"""Bounded capture of documentary repository sources."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .models import CapturedSource, SourceKind

_README_RE = re.compile(r"^readme(?:[_-]([a-z]{2,3}(?:[-_][a-z]{2,4})?))?(?:\.(?:md|rst|txt))?$", re.IGNORECASE)
_NAME_KINDS = (("authors", SourceKind.AUTHORS), ("maintainers", SourceKind.MAINTAINERS), ("contributors", SourceKind.AUTHORS))
_PACKAGE_NAMES = {"pyproject.toml", "setup.cfg", "package.json", "cargo.toml", "go.mod", "gemfile"}


def capture_sources(repository: Path, *, max_document_bytes: int, max_source_bytes: int) -> list[CapturedSource]:
    candidates = _candidates(repository)
    captured: list[CapturedSource] = []
    remaining = max_source_bytes
    for path, kind, translation in candidates:
        if remaining <= 0:
            break
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\0" in raw[:8192]:
            continue
        allowed = min(max_document_bytes, remaining)
        chunk = raw[:allowed]
        encoding = "utf-8-sig" if chunk.startswith(b"\xef\xbb\xbf") else "utf-8"
        text = chunk.decode(encoding, errors="replace")
        captured.append(
            CapturedSource(
                path=path.relative_to(repository),
                kind=kind,
                translation=translation,
                content=text,
                content_hash=hashlib.sha256(chunk).hexdigest(),
                byte_count=len(chunk),
                truncated=len(raw) > len(chunk),
                encoding=encoding,
            )
        )
        remaining -= len(chunk)
    return captured


def _candidates(repository: Path) -> list[tuple[Path, SourceKind, bool]]:
    try:
        entries = [entry for entry in repository.iterdir() if entry.is_file() and not entry.is_symlink()]
    except OSError:
        return []
    ranked: list[tuple[int, str, Path, SourceKind, bool]] = []
    for entry in entries:
        name = entry.name
        readme = _README_RE.fullmatch(name)
        if readme:
            translation = bool(readme.group(1))
            priority = 0 if name.casefold() in {"readme", "readme.md", "readme.rst", "readme.txt"} else 10
            ranked.append((priority, name.casefold(), entry, SourceKind.README, translation))
            continue
        folded = name.casefold()
        matched_kind = next((kind for prefix, kind in _NAME_KINDS if folded.startswith(prefix)), None)
        if matched_kind:
            ranked.append((20, folded, entry, matched_kind, False))
        elif folded in _PACKAGE_NAMES:
            ranked.append((30, folded, entry, SourceKind.PACKAGE, False))
    return [(path, kind, translation) for _, _, path, kind, translation in sorted(ranked)]
