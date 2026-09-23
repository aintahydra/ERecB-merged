"""Stable domain types shared across ghintel modules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class RemoteRole(StrEnum):
    ORIGIN = "origin"
    UPSTREAM = "upstream"
    OTHER = "other"


class SourceKind(StrEnum):
    README = "readme"
    AUTHORS = "authors"
    MAINTAINERS = "maintainers"
    PACKAGE = "package"


class LanguageCategory(StrEnum):
    CHINESE = "Chinese"
    RUSSIAN = "Russian"
    SLAVIC_OTHER = "Slavic-other"
    KOREAN = "Korean"
    JAPANESE = "Japanese"
    ARABIC = "Arabic"
    HEBREW = "Hebrew"
    HINDI = "Hindi"
    ENGLISH = "English"
    UNKNOWN = "Unknown"


class LanguageMethod(StrEnum):
    EXPLICIT_STATEMENT = "explicit-statement"
    UNICODE_SCRIPT = "unicode-script"
    LANGUAGE_DETECTOR = "language-detector"
    GEMINI = "gemini"
    CLAUDE = "claude"
    OLLAMA = "ollama"
    COMBINED = "combined"


class Confidence(StrEnum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    UNKNOWN = "Unknown"


@dataclass(frozen=True, slots=True)
class GithubRepository:
    owner: str
    name: str

    @property
    def identity_key(self) -> str:
        return f"github.com/{self.owner.casefold()}/{self.name.casefold()}"

    @property
    def canonical_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"


@dataclass(frozen=True, slots=True)
class Remote:
    name: str
    role: RemoteRole
    direction: str
    raw_url: str
    repository: GithubRepository | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class RepositoryLocation:
    path: Path
    git_kind: str
    remotes: tuple[Remote, ...]
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class CapturedSource:
    path: Path
    kind: SourceKind
    translation: bool
    content: str
    content_hash: str
    byte_count: int
    truncated: bool
    encoding: str
