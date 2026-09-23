"""Strict normalization for GitHub repository remote addresses."""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from .models import GithubRepository

_SCP_RE = re.compile(r"^(?:(?P<user>[^@\s/:]+)@)?(?P<host>github\.com):(?P<path>[^\s]+)$", re.IGNORECASE)
_VALID_PART = re.compile(r"^[^\s/\\?#:@]+$")
_ALLOWED_SCHEMES = {"http", "https", "git", "ssh"}


def normalize_github_url(value: str) -> GithubRepository:
    raw = value.strip()
    if not raw or any(char.isspace() for char in raw):
        raise ValueError("GitHub remote URL must be non-empty and contain no whitespace")

    scp = _SCP_RE.fullmatch(raw)
    if scp:
        return _from_path(scp.group("path"))

    parsed = urlsplit(raw)
    if parsed.scheme.casefold() not in _ALLOWED_SCHEMES:
        raise ValueError("unsupported GitHub URL scheme")
    if parsed.query or parsed.fragment:
        raise ValueError("GitHub URL must not contain a query or fragment")
    if not parsed.hostname or parsed.hostname.casefold() != "github.com":
        raise ValueError("only github.com URLs are supported")
    if parsed.scheme.casefold() in {"http", "https"} and (parsed.username or parsed.password):
        raise ValueError("HTTP GitHub URLs must not contain credentials")
    if parsed.scheme.casefold() == "ssh" and parsed.username not in {None, "git"}:
        raise ValueError("SSH GitHub URLs may only use the git user")
    if parsed.port not in {None, 22, 80, 443}:
        raise ValueError("unsupported GitHub URL port")
    return _from_path(parsed.path)


def _from_path(path: str) -> GithubRepository:
    parts = [unquote(part) for part in path.split("/") if part]
    if len(parts) != 2:
        raise ValueError("GitHub repository URL must contain exactly owner/repository")
    owner, name = parts
    if name.casefold().endswith(".git"):
        name = name[:-4]
    if not owner or not name or not _VALID_PART.fullmatch(owner) or not _VALID_PART.fullmatch(name):
        raise ValueError("invalid GitHub owner or repository name")
    if owner in {".", ".."} or name in {".", ".."}:
        raise ValueError("GitHub owner and repository cannot be path components")
    return GithubRepository(owner=owner, name=name)
