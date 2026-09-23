from __future__ import annotations

import os
import stat
from collections.abc import Iterator
from pathlib import Path

from yararuler.errors import ConfigurationError
from yararuler.models import Candidate, ScanErrorRecord

MAX_TRAVERSAL_DEPTH = 256


def report_path(path: Path, target: Path) -> str:
    absolute = path.resolve(strict=False)
    try:
        return absolute.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        try:
            return absolute.relative_to(target.parent).as_posix()
        except ValueError:
            return absolute.as_posix()


class FileDiscoverer:
    def __init__(
        self,
        target: Path,
        *,
        follow_symlinks: bool = False,
        excluded_paths: set[Path] | None = None,
    ) -> None:
        self.target = target.resolve()
        if not self.target.is_dir():
            raise ConfigurationError(f"target directory does not exist: {self.target}")
        self.follow_symlinks = follow_symlinks
        self.excluded_paths = {path.resolve(strict=False) for path in (excluded_paths or set())}
        self.errors: list[ScanErrorRecord] = []

    def _error(self, path: Path, operation: str, exc: BaseException) -> None:
        self.errors.append(
            ScanErrorRecord(
                path=report_path(path, self.target),
                operation=operation,
                category=type(exc).__name__,
                message=str(exc).replace("\x00", "")[:1000],
            )
        )

    def iter_files(self) -> Iterator[Candidate]:
        stack: list[tuple[Path, int]] = [(self.target, 0)]
        visited: set[tuple[int, int]] = set()
        sequence = 0
        while stack:
            directory, depth = stack.pop()
            if depth > MAX_TRAVERSAL_DEPTH:
                self.errors.append(
                    ScanErrorRecord(
                        report_path(directory, self.target),
                        "traverse",
                        "maximum_depth",
                        f"maximum traversal depth {MAX_TRAVERSAL_DEPTH} exceeded",
                    )
                )
                continue
            try:
                directory_stat = directory.stat(follow_symlinks=self.follow_symlinks)
                identity = (directory_stat.st_dev, directory_stat.st_ino)
                if identity in visited:
                    continue
                visited.add(identity)
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except OSError as exc:
                self._error(directory, "scandir", exc)
                continue

            child_directories: list[Path] = []
            for entry in entries:
                path = Path(entry.path)
                try:
                    if entry.is_symlink() and not self.follow_symlinks:
                        continue
                    info = entry.stat(follow_symlinks=self.follow_symlinks)
                except OSError as exc:
                    self._error(path, "stat", exc)
                    continue
                if stat.S_ISDIR(info.st_mode):
                    child_directories.append(path)
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                resolved = path.resolve(strict=False)
                if resolved in self.excluded_paths:
                    continue
                if not os.access(path, os.R_OK):
                    self.errors.append(
                        ScanErrorRecord(
                            report_path(path, self.target),
                            "access",
                            "permission_denied",
                            "file is not readable",
                        )
                    )
                    continue
                yield Candidate(sequence, resolved, report_path(resolved, self.target))
                sequence += 1
            for child in reversed(child_directories):
                stack.append((child, depth + 1))
