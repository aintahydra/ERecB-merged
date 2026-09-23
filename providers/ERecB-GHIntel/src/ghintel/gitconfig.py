"""A deliberately small, non-executing parser for Git remote configuration."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from .github_urls import normalize_github_url
from .models import Remote, RemoteRole

_SECTION_RE = re.compile(r'^\s*\[\s*(?P<name>[A-Za-z0-9.-]+)(?:\s+"(?P<subsection>(?:[^"\\]|\\.)*)")?\s*\]\s*$')
_KEY_RE = re.compile(r"^\s*(?P<key>[A-Za-z][A-Za-z0-9-]*)\s*=\s*(?P<value>.*)$")


@dataclass(frozen=True, slots=True)
class ParsedGitConfig:
    remotes: tuple[Remote, ...]
    diagnostics: tuple[str, ...]


def parse_git_config(path: Path, *, max_bytes: int = 1_048_576) -> ParsedGitConfig:
    try:
        data = path.read_bytes()
    except OSError as error:
        return ParsedGitConfig((), (f"could not read Git config: {error}",))
    if len(data) > max_bytes:
        return ParsedGitConfig((), (f"Git config exceeds {max_bytes} bytes",))
    text = data.decode("utf-8", errors="replace")
    return parse_git_config_text(text)


def parse_git_config_text(text: str) -> ParsedGitConfig:
    section: tuple[str, str | None] | None = None
    remote_values: list[tuple[str, str, str]] = []
    diagnostics: list[str] = []
    logical_lines = _logical_lines(text)
    for line_number, raw_line in logical_lines:
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        section_match = _SECTION_RE.match(line)
        if section_match:
            subsection = section_match.group("subsection")
            section = (section_match.group("name").casefold(), _unescape(subsection) if subsection else None)
            continue
        key_match = _KEY_RE.match(line)
        if not key_match:
            diagnostics.append(f"line {line_number}: unsupported Git config syntax")
            continue
        key, value = key_match.group("key").casefold(), _unquote(key_match.group("value").strip())
        if section is None:
            diagnostics.append(f"line {line_number}: key outside a section")
            continue
        if section[0] in {"include", "includeif"}:
            diagnostics.append(f"line {line_number}: ignored Git config include directive")
            continue
        if section[0] == "remote" and section[1] and key in {"url", "pushurl"}:
            remote_values.append((section[1], "push" if key == "pushurl" else "fetch", value))

    remotes: list[Remote] = []
    for name, direction, raw_url in remote_values:
        role = RemoteRole.ORIGIN if name.casefold() == "origin" else RemoteRole.UPSTREAM if name.casefold() == "upstream" else RemoteRole.OTHER
        try:
            repository = normalize_github_url(raw_url)
            remotes.append(Remote(name, role, direction, raw_url, repository))
        except ValueError as error:
            remotes.append(Remote(name, role, direction, raw_url, None, str(error)))
    return ParsedGitConfig(tuple(remotes), tuple(diagnostics))


def _logical_lines(text: str) -> list[tuple[int, str]]:
    result: list[tuple[int, str]] = []
    pending = ""
    start = 1
    for number, line in enumerate(text.splitlines(), start=1):
        if not pending:
            start = number
        if line.rstrip().endswith("\\") and not line.rstrip().endswith("\\\\"):
            pending += line.rstrip()[:-1]
            continue
        result.append((start, pending + line))
        pending = ""
    if pending:
        result.append((start, pending))
    return result


def _strip_comment(value: str) -> str:
    quoted = False
    escaped = False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char in {"#", ";"}:
            return value[:index]
    return value


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    return _unescape(value)


def _unescape(value: str) -> str:
    return value.replace(r"\\", "\\").replace(r'\"', '"').replace(r"\n", "\n").replace(r"\t", "\t")
