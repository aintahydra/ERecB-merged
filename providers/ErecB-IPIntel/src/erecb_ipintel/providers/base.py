from __future__ import annotations

from abc import ABC, abstractmethod

from ..models import NormalizedIntelRecord, ProviderRawResult


class ProviderError(RuntimeError):
    pass


class CredentialError(ProviderError):
    pass


class ProviderAdapter(ABC):
    name: str

    @abstractmethod
    def validate_credentials(self) -> None:
        raise NotImplementedError

    @abstractmethod
    def fetch(self, ip: str) -> ProviderRawResult:
        raise NotImplementedError

    @abstractmethod
    def normalize(self, ip: str, raw: ProviderRawResult, store_raw_json: bool = True) -> NormalizedIntelRecord:
        raise NotImplementedError
