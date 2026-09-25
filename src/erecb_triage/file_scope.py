"""Shared, bounded candidate predicate for offline capture adapters."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from erecb_triage.fileintel.classifier import EXECUTABLE_EXTENSIONS


_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


def executable_candidate(path: Path, reader: BinaryIO) -> bool:
    """Classify without executing content; leave a seekable stream at its start."""
    sample = reader.read(8192)
    reader.seek(0)
    return (sample.startswith(_MAGIC)
            or sample.startswith(b"#!") and bool(sample[2:].strip().split(None, 1))
            or path.suffix.lower() in EXECUTABLE_EXTENSIONS)
