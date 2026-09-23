from __future__ import annotations

import fnmatch
import logging
import re
from pathlib import Path
from re import Pattern

from yararuler.errors import ConfigurationError
from yararuler.models import Candidate

LOGGER = logging.getLogger(__name__)
HEADER_BYTES = 8192
SCRIPT_EXTENSIONS = {
    ".ps1",
    ".bat",
    ".cmd",
    ".sh",
    ".py",
    ".pl",
    ".php",
    ".rb",
    ".js",
    ".vbs",
}
BINARY_EXTENSIONS = {".exe", ".dll", ".sys", ".bin", ".elf", ".so", ".dylib"}
MAGIC_HEADERS = (
    b"MZ",
    b"\x7fELF",
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
)
EXECUTABLE_MIME_FRAGMENTS = (
    "executable",
    "x-sh",
    "x-python",
    "x-perl",
    "x-php",
    "x-ruby",
    "javascript",
)


class CandidateFilter:
    def __init__(
        self,
        *,
        selector: str,
        globs: list[str] | None = None,
        regexes: list[str] | None = None,
        max_file_size_bytes: int = 0,
    ) -> None:
        if selector not in {"all", "exec-only"}:
            raise ConfigurationError(f"invalid selector: {selector}")
        self.selector = selector
        self.globs = globs or []
        self.max_file_size_bytes = max_file_size_bytes
        try:
            self.regexes: list[Pattern[str]] = [re.compile(value) for value in (regexes or [])]
        except re.error as exc:
            raise ConfigurationError(f"invalid regular expression: {exc}") from exc
        self._magic = None
        self._magic_checked = False

    def _mime_is_executable(self, path: Path) -> bool:
        if not self._magic_checked:
            self._magic_checked = True
            try:
                import magic

                self._magic = magic.Magic(mime=True)
            except (ImportError, OSError) as exc:
                LOGGER.debug(
                    "libmagic unavailable; using header and extension heuristics: %s",
                    exc,
                )
                self._magic = None
        if self._magic is None:
            return False
        try:
            mime = str(self._magic.from_file(str(path))).lower()
        except Exception as exc:
            LOGGER.warning("libmagic failed; continuing with other heuristics: %s", exc)
            self._magic = None
            return False
        return any(fragment in mime for fragment in EXECUTABLE_MIME_FRAGMENTS)

    def _exec_candidate(self, path: Path) -> bool:
        suffix = path.suffix.lower()
        if suffix in SCRIPT_EXTENSIONS or suffix in BINARY_EXTENSIONS:
            return True
        with path.open("rb") as handle:
            header = handle.read(HEADER_BYTES)
        if any(header.startswith(signature) for signature in MAGIC_HEADERS):
            return True
        first_line = header.splitlines()[0] if header else b""
        if first_line.startswith(b"#!"):
            interpreter = first_line[2:512].strip().split(b" ", 1)[0]
            if interpreter:
                return True
        return self._mime_is_executable(path)

    def accepts(self, candidate: Candidate) -> bool:
        if self.max_file_size_bytes and candidate.path.stat().st_size > self.max_file_size_bytes:
            return False
        if self.selector == "exec-only" and not self._exec_candidate(candidate.path):
            return False
        if self.globs and not any(
            fnmatch.fnmatchcase(candidate.path.name, pattern) for pattern in self.globs
        ):
            return False
        return not (
            self.regexes and not any(regex.search(candidate.file_path) for regex in self.regexes)
        )
