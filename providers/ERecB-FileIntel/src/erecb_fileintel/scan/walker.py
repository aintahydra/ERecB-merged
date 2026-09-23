from __future__ import annotations

from pathlib import Path

from erecb_fileintel.errors import RecoverableScanError
from erecb_fileintel.models import FileCandidate


class FileWalker:
    def __init__(self, follow_symlinks: bool, max_file_size_bytes: int | None) -> None:
        self.follow_symlinks = follow_symlinks
        self.max_file_size_bytes = max_file_size_bytes

    def walk(self, root: Path):
        yield from self._walk(root)

    def _walk(self, directory: Path):
        try:
            entries = sorted(directory.iterdir(), key=lambda p: str(p))
        except OSError as exc:
            yield RecoverableScanError("scan", exc.__class__.__name__, str(exc))
            return

        for entry in entries:
            try:
                if entry.is_symlink() and not self.follow_symlinks:
                    continue
                if entry.is_dir():
                    yield from self._walk(entry)
                    continue
                if not entry.is_file():
                    continue
                stat = entry.stat()
                if self.max_file_size_bytes is not None and stat.st_size > self.max_file_size_bytes:
                    yield RecoverableScanError("scan", "FileTooLarge", f"file exceeds max size: {stat.st_size}")
                    continue
                yield FileCandidate(entry.resolve(), entry.name, stat.st_size)
            except OSError as exc:
                yield RecoverableScanError("scan", exc.__class__.__name__, str(exc))
