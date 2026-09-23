from __future__ import annotations

from pathlib import Path


MAGIC_INDICATORS = (
    "pe32",
    "pe32+",
    "msi installer",
    "windows installer",
    "elf 32-bit",
    "elf 64-bit",
    "elf",
    "shared object",
    "mach-o",
    "dex",
    "dalvik",
    "posix shell script",
    "bourne-again shell script",
    "powershell",
)

EXTENSION_INDICATORS = {
    ".exe",
    ".dll",
    ".sys",
    ".ocx",
    ".msi",
    ".so",
    ".dylib",
    ".app",
    ".dex",
    ".apk",
    ".ps1",
    ".sh",
    ".bash",
}


def executable_reason(path: Path, magic_text: str) -> str | None:
    lowered = magic_text.lower()
    for indicator in MAGIC_INDICATORS:
        if indicator in lowered:
            return f"magic: {indicator}"
    suffix = path.suffix.lower()
    if suffix in EXTENSION_INDICATORS:
        return f"extension fallback: {suffix}"
    return None

