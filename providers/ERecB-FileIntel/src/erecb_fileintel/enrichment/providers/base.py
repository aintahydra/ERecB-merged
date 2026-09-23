from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from erecb_fileintel.models import NormalizedIntel


class IntelligenceProvider(ABC):
    name: str
    supported_hash_types: tuple[str, ...]

    @abstractmethod
    def lookup(self, hash_value: str, hash_type: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, raw_response: dict[str, Any], raw_response_path: str | None = None) -> NormalizedIntel:
        raise NotImplementedError

