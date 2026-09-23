"""Small serializable records emitted by the YARA adapter."""

from __future__ import annotations

from typing import TypedDict


class YaraMatch(TypedDict, total=False):
    type: str
    source_path: str
    display_path: str
    sha256_hash: str
    md5_hash: str
    size_bytes: int
    namespace: str
    rule: str
    tags: list[str]
    meta: dict[str, str | int | bool]
    strings: list[dict[str, int | str]]
    strings_truncated: bool
    cache_generation: str
    provenance: dict[str, str]
