from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import requests

from erecb_fileintel.config import CtxIoConfig, EnrichmentConfig
from erecb_fileintel.enrichment.merge import normalize_hash, unique_clean
from erecb_fileintel.errors import ProviderAuthError, ProviderError, ProviderRateLimitError
from erecb_fileintel.models import NormalizedIntel

from .base import IntelligenceProvider


class CtxIoProvider(IntelligenceProvider):
    name = "ctx_io"
    supported_hash_types = ("sha256", "sha1", "md5")

    def __init__(self, config: CtxIoConfig, enrichment_config: EnrichmentConfig) -> None:
        self.config = config
        self.enrichment_config = enrichment_config
        self.api_key = self._read_api_key(config.api_key_path)

    def lookup(self, hash_value: str, hash_type: str) -> dict[str, Any]:
        if hash_type not in self.supported_hash_types:
            raise ProviderError("provider_error", f"unsupported hash type for CTX.IO: {hash_type}")

        url = f"{self.config.base_url}/file/report/{hash_value}"
        last_error: ProviderError | None = None
        for _attempt in range(self.enrichment_config.provider_retry_count + 1):
            try:
                response = requests.get(
                    url,
                    headers={"x-api-key": self.api_key},
                    timeout=self.enrichment_config.provider_timeout_seconds,
                )
            except requests.Timeout as exc:
                last_error = ProviderError("timeout", str(exc))
                continue
            except requests.RequestException as exc:
                last_error = ProviderError("network_error", str(exc))
                continue

            if response.status_code in (401, 403):
                raise ProviderAuthError("CTX.IO authentication failed", response.status_code)
            if response.status_code == 429:
                raise ProviderRateLimitError("CTX.IO rate limit reached", response.status_code)
            if response.status_code == 404:
                return {"_http_status": 404, "_provider_status": "not_found"}
            if response.status_code >= 500:
                last_error = ProviderError("provider_error", response.text[:500], response.status_code)
                continue
            if response.status_code >= 400:
                raise ProviderError("provider_error", response.text[:500], response.status_code)

            try:
                data = response.json()
            except json.JSONDecodeError as exc:
                raise ProviderError("parse_error", str(exc), response.status_code) from exc
            data["_http_status"] = response.status_code
            return data

        if last_error is not None:
            raise last_error
        raise ProviderError("provider_error", "CTX.IO lookup failed")

    def normalize(self, raw_response: dict[str, Any], raw_response_path: str | None = None) -> NormalizedIntel:
        provider_status = raw_response.get("_provider_status")
        if provider_status == "not_found":
            return self._empty_result("not_found", raw_response_path)

        ctx_result = raw_response.get("ctx_result") or {}
        if ctx_result.get("result_code") != 200:
            return self._empty_result("provider_error", raw_response_path, str(ctx_result.get("result_msg", "")))

        data = raw_response.get("ctx_data")
        if not isinstance(data, dict):
            return self._empty_result("not_found", raw_response_path)

        hash_data = data.get("hash") if isinstance(data.get("hash"), dict) else {}
        detect = data.get("detect")
        if detect is None:
            malicious = "unknown"
        elif str(detect).lower() == "normal":
            malicious = "no"
        else:
            malicious = "yes"

        tags = []
        for key in ("tags", "threat_types"):
            values = data.get(key) or []
            if isinstance(values, list):
                tags.extend(str(value) for value in values)

        file_names = data.get("file_names") or []
        if not isinstance(file_names, list):
            file_names = []

        return NormalizedIntel(
            provider_name=self.name,
            provider_status="success",
            sha256_hash=normalize_hash(hash_data.get("sha256")),
            md5_hash=normalize_hash(hash_data.get("md5")),
            magic=str(data["file_type"]).strip() if data.get("file_type") else None,
            malicious=malicious,
            tags=unique_clean(tags),
            file_names=unique_clean([str(value) for value in file_names]),
            raw_response_path=raw_response_path,
            error_message=None,
        )

    def _empty_result(
        self,
        status: str,
        raw_response_path: str | None,
        error_message: str | None = None,
    ) -> NormalizedIntel:
        return NormalizedIntel(
            provider_name=self.name,
            provider_status=status,
            sha256_hash=None,
            md5_hash=None,
            magic=None,
            malicious=None,
            tags=(),
            file_names=(),
            raw_response_path=raw_response_path,
            error_message=error_message,
        )

    @staticmethod
    def _read_api_key(path: Path) -> str:
        return path.read_text(encoding="utf-8").strip()

