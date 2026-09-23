"""Strict, producer-compatible normalization for GitHub repository roots."""
from __future__ import annotations

import re
from dataclasses import dataclass


_PART = r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})"
_WEB = re.compile(rf"(?:https?|git)://github\.com/({_PART})/({_PART})(?:\.git)?/?", re.I)
_SSH = re.compile(rf"ssh://git@github\.com(?::([0-9]{{1,5}}))?/({_PART})/({_PART})(?:\.git)?/?", re.I)
_SCP = re.compile(rf"git@github\.com:({_PART})/({_PART})(?:\.git)?/?", re.I)
_BARE = re.compile(rf"github\.com/({_PART})/({_PART})(?:\.git)?/?", re.I)


@dataclass(frozen=True)
class RepositoryIdentity:
    identity_key: str
    canonical_url: str
    owner: str
    repository: str


def normalize_repository(value: str) -> RepositoryIdentity | None:
    if not isinstance(value, str) or not value or len(value) > 2048:
        return None
    if any(ord(char) < 33 or ord(char) == 127 or char in "\\?#" for char in value):
        return None
    match = _WEB.fullmatch(value)
    groups: tuple[str, str] | None = None
    if match:
        groups = match.group(1), match.group(2)
    else:
        match = _SSH.fullmatch(value)
        if match:
            port = match.group(1)
            if port is not None and not 1 <= int(port) <= 65535:
                return None
            groups = match.group(2), match.group(3)
        else:
            match = _SCP.fullmatch(value) or _BARE.fullmatch(value)
            if match:
                groups = match.group(1), match.group(2)
    if groups is None:
        return None
    owner, repository = groups
    if owner in {".", ".."} or repository in {".", ".."}:
        return None
    if repository.lower().endswith(".git"):
        repository = repository[:-4]
    if not repository or repository in {".", ".."}:
        return None
    return RepositoryIdentity(
        identity_key=f"github.com/{owner.casefold()}/{repository.casefold()}",
        canonical_url=f"https://github.com/{owner}/{repository}", owner=owner, repository=repository,
    )
