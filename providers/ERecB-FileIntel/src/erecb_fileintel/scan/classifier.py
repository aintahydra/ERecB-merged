from __future__ import annotations

from pathlib import Path

from erecb_fileintel.models import ClassificationResult

from .executable_rules import executable_reason


class FileClassifier:
    def __init__(self) -> None:
        try:
            import magic  # type: ignore
        except ImportError:
            magic = None
        self._magic = magic

    def classify(self, path: Path) -> ClassificationResult:
        magic_text = self._detect_magic(path)
        reason = executable_reason(path, magic_text)
        return ClassificationResult(
            path=path,
            magic=magic_text,
            is_executable=reason is not None,
            reason=reason or "not executable",
        )

    def _detect_magic(self, path: Path) -> str:
        if self._magic is None:
            return "unknown"
        try:
            return str(self._magic.from_file(str(path)))
        except Exception as exc:
            return f"magic error: {exc}"

