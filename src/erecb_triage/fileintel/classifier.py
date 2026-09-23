"""Magic-first classification from bounded bytes; never execute captured files."""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Literal


MAGIC_SAMPLE_BYTES = 8192
MAGIC_INDICATORS = (
    "pe32", "pe32+", "msi installer", "windows installer", "elf 32-bit", "elf 64-bit",
    "elf", "shared object", "mach-o", "dex", "dalvik", "posix shell script",
    "bourne-again shell script", "powershell",
)
EXECUTABLE_EXTENSIONS = frozenset({
    ".exe", ".dll", ".sys", ".ocx", ".msi", ".so", ".dylib", ".app", ".dex",
    ".apk", ".ps1", ".sh", ".bash",
})
Availability = Literal["available", "degraded", "unavailable"]
MagicDescription = Callable[[bytes], str | None]


def _load_magic() -> MagicDescription:
    return importlib.import_module("magic").Magic(mime=False).from_buffer


@dataclass(frozen=True)
class Classification:
    magic: str | None
    reason: str | None

    @property
    def is_executable(self) -> bool:
        return self.reason is not None


class ExecutableClassifier:
    def __init__(self, *, use_magic: bool = True, extension_fallback: bool = True,
                 describe: MagicDescription | None = None) -> None:
        if type(use_magic) is not bool or type(extension_fallback) is not bool:
            raise ValueError("classifier settings must be boolean")
        if not use_magic and not extension_fallback:
            raise ValueError("at least one classifier method must be enabled")
        self.extension_fallback = extension_fallback
        self.describe = None
        self.unavailable_reason: str | None = None
        self.availability: Availability = "available"
        if use_magic:
            try:
                self.describe = describe if describe is not None else _load_magic()
            except Exception as exc:
                self.unavailable_reason = f"magic detection unavailable: {exc}"
                self.availability = "degraded" if extension_fallback else "unavailable"

    def classify(self, path: Path, sample: bytes) -> Classification:
        if self.availability == "unavailable":
            raise RuntimeError(self.unavailable_reason)
        if len(sample) > MAGIC_SAMPLE_BYTES:
            raise ValueError("classification sample exceeds bounded header size")
        description = self.describe(sample) if self.describe is not None else None
        if description is not None and not isinstance(description, str):
            raise TypeError("magic description must be a string or null")
        normalized = (description or "").strip().lower()
        for indicator in MAGIC_INDICATORS:
            if indicator in normalized:
                return Classification(description, f"magic: {indicator}")
        extension = path.suffix.lower()
        generic = normalized.split(",", 1)[0].strip() in {"", "data", "ascii text", "unicode text"}
        apk = extension == ".apk" and normalized.startswith("zip archive data")
        if self.extension_fallback and (generic or apk) and extension in EXECUTABLE_EXTENSIONS:
            return Classification(description, f"extension fallback: {extension}")
        return Classification(description, None)
