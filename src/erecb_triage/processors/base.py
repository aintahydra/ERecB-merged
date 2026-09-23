from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ProcessorError:
    path: Path
    message: str
    code: str


@dataclass(frozen=True)
class ProcessorResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[ProcessorError] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=dict)
    statuses: list[dict[str, Any]] = field(default_factory=list)


class Processor(ABC):
    name: str

    def accepts(self, input_records: list[dict[str, Any]], context: Any) -> bool:
        return True

    @abstractmethod
    def process(
        self,
        input_records: list[dict[str, Any]],
        context: Any,
    ) -> ProcessorResult:
        raise NotImplementedError
