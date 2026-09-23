from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from ..config import CtxIoConfig
from ..db import raw_json
from ..models import NormalizedIntelRecord, ProviderRawResult
from .base import CredentialError, ProviderAdapter


class CtxIoProvider(ProviderAdapter):
    name = "ctx_io"

    def __init__(self, config: CtxIoConfig, root: Path) -> None:
        self.config = config
        self.root = root
        self.api_key = self._resolve_api_key()

    def validate_credentials(self) -> None:
        if not self.api_key:
            raise CredentialError("CTX.IO API key is not configured")

    def fetch(self, ip: str) -> ProviderRawResult:
        self.validate_credentials()
        url = f"{self.config.base_url.rstrip('/')}/ip/report/{ip}"
        last_error = None
        for attempt in range(self.config.retry_count + 1):
            try:
                request = urllib.request.Request(url, headers={"x-api-key": self.api_key or ""}, method="GET")
                with urllib.request.urlopen(request, timeout=self.config.timeout_seconds) as response:
                    body = response.read()
                    data = json.loads(body.decode("utf-8"))
                    return ProviderRawResult(status="success", status_code=response.status, data=data)
            except urllib.error.HTTPError as exc:
                body = exc.read()
                data = _decode_json(body)
                if exc.code in {429, 500, 502, 503, 504} and attempt < self.config.retry_count:
                    time.sleep(self.config.retry_backoff_seconds * (attempt + 1))
                    continue
                status = "not_found" if exc.code == 404 else "failed"
                return ProviderRawResult(status=status, status_code=exc.code, data=data, error_summary=f"HTTP {exc.code}")
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                last_error = f"{exc.__class__.__name__}: {exc}"
                if attempt < self.config.retry_count:
                    time.sleep(self.config.retry_backoff_seconds * (attempt + 1))
                    continue
        return ProviderRawResult(status="failed", status_code=None, data=None, error_summary=last_error or "request failed")

    def normalize(self, ip: str, raw: ProviderRawResult, store_raw_json: bool = True) -> NormalizedIntelRecord:
        data = raw.data or {}
        ctx_data = data.get("ctx_data") if isinstance(data.get("ctx_data"), dict) else {}
        result = data.get("ctx_result") if isinstance(data.get("ctx_result"), dict) else {}
        request = data.get("request") if isinstance(data.get("request"), dict) else {}
        detect = ctx_data.get("detect")
        return NormalizedIntelRecord(
            ip=ip,
            ipv4=_str_or_none(ctx_data.get("ipv4")),
            ipv6=_str_or_none(ctx_data.get("ipv6")),
            country_code=_str_or_none(ctx_data.get("country_code")),
            whois=_str_or_none(ctx_data.get("whois")),
            reverse_dns=_string_list(ctx_data.get("reverse_dns")),
            malicious="Yes" if detect and detect != "normal" else "No",
            related_iocs=_flatten_iocs(ctx_data.get("apt_ioc_indicator")),
            related_actors=_flatten_actors(ctx_data.get("apt_threat_actors")),
            provider_name=self.name,
            provider_result_code=_str_or_none(result.get("result_code")),
            provider_transaction_id=_str_or_none(request.get("ctx_transaction_id")),
            raw_response_json=raw_json(data, store_raw_json),
        )

    def _resolve_api_key(self) -> str | None:
        candidates = [
            self.config.api_key,
            os.environ.get("CTX_IO_API_KEY"),
            _read_key_file(self.root / "ctx_io_api_key.txt"),
        ]
        for candidate in candidates:
            if candidate and candidate.strip():
                return candidate.strip()
        return None


def _read_key_file(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _decode_json(body: bytes) -> dict[str, Any] | None:
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        return None


def _str_or_none(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return _dedupe(str(item).strip() for item in value if item is not None)


def _flatten_iocs(value: Any) -> list[str]:
    leaves: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for item in node.values():
                walk(item)
        elif isinstance(node, list):
            for item in node:
                walk(item)
        elif node is not None:
            leaves.append(str(node).strip())

    walk(value)
    return _dedupe(leaves)


def _flatten_actors(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    actors: list[str] = []
    for actor in value:
        if not isinstance(actor, dict):
            continue
        country = str(actor.get("country_code") or "").upper()
        names = []
        name = _str_or_none(actor.get("name"))
        if name:
            names.append(name)
        aliases = actor.get("aliases")
        if isinstance(aliases, list):
            names.extend(str(alias).strip() for alias in aliases if str(alias).strip())
        if names:
            actors.append(f"({country}){'/'.join(names)}")
    return _dedupe(actors)


def _dedupe(values: Any) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            result.append(text)
    return result
