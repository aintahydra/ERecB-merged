from __future__ import annotations

from collections.abc import Callable
from typing import TextIO


ProgressCallback = Callable[[str, int, int], None]


class PercentageProgress:
    """Print bounded progress updates without polluting command stdout."""

    def __init__(self, stream: TextIO, step: int = 10) -> None:
        if step < 1 or step > 100:
            raise ValueError("progress step must be between 1 and 100")
        self.stream = stream
        self.step = step
        self._last_percent: dict[str, int] = {}

    def update(self, stage: str, completed: int, total: int) -> None:
        if total < 0:
            raise ValueError("progress total cannot be negative")
        if completed < 0:
            raise ValueError("progress completed count cannot be negative")

        if total == 0:
            percent = 100
            completed = 0
        else:
            completed = min(completed, total)
            raw_percent = (completed * 100) // total
            percent = 100 if completed == total else (raw_percent // self.step) * self.step

        previous = self._last_percent.get(stage)
        if previous is not None and percent <= previous:
            return

        self._last_percent[stage] = percent
        print(f"{stage}: {percent}% ({completed}/{total})", file=self.stream, flush=True)
