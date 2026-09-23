from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from erecb_triage.events import WatchEvent


@dataclass(frozen=True)
class StableCheck:
    enabled: bool = True
    interval_ms: int = 250
    unchanged_checks: int = 3


class PollingWatcher:
    def __init__(
        self,
        watch_path: Path,
        stable_check: StableCheck | None = None,
        poll_interval_ms: int = 500,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.watch_path = watch_path.resolve()
        self.stable_check = stable_check or StableCheck()
        self.poll_interval_ms = poll_interval_ms
        self._sleep = sleeper
        self.watch_path.mkdir(parents=True, exist_ok=True)
        self._seen = self._snapshot_direct_children()
        self._retry: set[Path] = set()

    def scan_existing(self, on_candidate: Callable[[Path], object] | None = None) -> list[WatchEvent]:
        """Return stable direct children, optionally announcing each before its stability check."""
        events: list[WatchEvent] = []
        for path in sorted(self.watch_path.iterdir()):
            if on_candidate is not None:
                on_candidate(path)
            event = self._event_when_stable(path)
            if event is not None:
                events.append(event)
        self._seen = self._snapshot_direct_children()
        return events

    def watch_forever(
        self, enqueue: Callable[[WatchEvent], object], drain: Callable[[], object] | None = None,
        on_candidate: Callable[[Path], object] | None = None,
    ) -> None:
        for event in self.events(on_candidate=on_candidate):
            enqueue(event)
            if drain is not None:
                drain()

    def retry(self, path: Path) -> None:
        if path.parent == self.watch_path:
            self._retry.add(path)

    def events(self, on_candidate: Callable[[Path], object] | None = None) -> Iterator[WatchEvent]:
        while True:
            current = self._snapshot_direct_children()
            pending = (current - self._seen) | (current & self._retry)
            self._retry.difference_update(pending)
            for path in sorted(pending):
                if on_candidate is not None:
                    on_candidate(path)
                event = self._event_when_stable(path)
                if event is not None:
                    yield event
            self._seen = current
            self._sleep(self.poll_interval_ms / 1000)

    def _event_when_stable(self, path: Path) -> WatchEvent | None:
        if path.is_symlink():
            return None
        if not self.stable_check.enabled:
            return self._make_event(path)

        previous: tuple[int, int, int] | None = None
        unchanged = 0
        while unchanged < self.stable_check.unchanged_checks:
            if path.is_symlink() or not path.exists():
                return None
            try:
                current = self._stability_signature(path)
            except OSError:
                return None
            if current == previous:
                unchanged += 1
            else:
                unchanged = 0
            previous = current
            self._sleep(self.stable_check.interval_ms / 1000)
        return self._make_event(path)

    def _make_event(self, path: Path) -> WatchEvent | None:
        try:
            if path.is_symlink() or not (path.is_file() or path.is_dir()):
                return None
            return WatchEvent.added(self.watch_path, path)
        except (OSError, ValueError):
            return None

    def _snapshot_direct_children(self) -> set[Path]:
        return {path for path in self.watch_path.iterdir() if not path.is_symlink()}

    def _stability_signature(self, path: Path) -> tuple[int, int, int]:
        if path.is_file():
            info = path.stat()
            return (1, info.st_size, info.st_mtime_ns)

        file_count = 0
        total_size = 0
        latest_mtime = path.stat().st_mtime_ns
        for directory, dirs, files in os.walk(path, followlinks=False):
            dirs[:] = [name for name in dirs if not (Path(directory) / name).is_symlink()]
            for name in dirs + files:
                try:
                    info = (Path(directory) / name).lstat()
                except FileNotFoundError:
                    continue
                latest_mtime = max(latest_mtime, info.st_mtime_ns)
                if stat.S_ISREG(info.st_mode):
                    file_count += 1
                    total_size += info.st_size
        return (file_count, total_size, latest_mtime)
