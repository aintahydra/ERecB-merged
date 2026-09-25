from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from erecb_fileintel.config import AppConfig
from erecb_fileintel.db.repository import Repository
from erecb_fileintel.errors import ProviderAuthError, ProviderError, ProviderRateLimitError
from erecb_fileintel.models import FileForEnrichment

from .providers.base import IntelligenceProvider
from .providers.ctx_io import CtxIoProvider


class EnrichmentService:
    def __init__(
        self,
        config: AppConfig,
        repository: Repository,
        providers: list[IntelligenceProvider] | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self.logger = logger or logging.getLogger(__name__)
        self.providers = providers if providers is not None else self._build_providers()
        self.disabled_providers: set[str] = set()

    def enrich_scan_job(self, scan_job_id: int) -> int:
        error_count = 0
        files = self.repository.get_files_for_enrichment(scan_job_id)
        for file in files:
            for provider in self.providers:
                if provider.name in self.disabled_providers:
                    continue
                if self.repository.should_skip_provider_lookup(
                    file.id,
                    provider.name,
                    self.config.enrichment.requery_success_after_days,
                    self.config.enrichment.requery_failure_after_hours,
                ):
                    continue
                error_count += self._lookup_file(file, provider)
        return error_count

    def enrich_hash(self, sha256_hash: str, md5_hash: str | None) -> str:
        """Query one imported indicator, bypassing age reuse for this explicit request."""
        file = self.repository.upsert_hash_only(sha256_hash, md5_hash)
        if not self.providers:
            return "error"
        statuses = []
        for provider in self.providers:
            self._lookup_file(file, provider)
            row = self.repository.conn.execute(
                "SELECT status FROM provider_lookups WHERE file_id = ? AND provider = ? "
                "ORDER BY id DESC LIMIT 1", (file.id, provider.name),
            ).fetchone()
            statuses.append(row["status"] if row else "provider_error")
        if "success" in statuses:
            return "success"
        # An unresolved imported hash belongs to homework, not the intelligence DB.
        # Preserve audit rows (their FK is SET NULL) but remove a hash-only placeholder.
        with self.repository.conn:
            self.repository.conn.execute(
                "DELETE FROM files WHERE id = ? AND malicious = 'unknown' AND magic IS NULL "
                "AND NOT EXISTS (SELECT 1 FROM file_observations WHERE file_id = ?) "
                "AND NOT EXISTS (SELECT 1 FROM tags WHERE file_id = ?) "
                "AND NOT EXISTS (SELECT 1 FROM file_names WHERE file_id = ?)",
                (file.id, file.id, file.id, file.id),
            )
        if "rate_limited" in statuses:
            return "rate_limited"
        if statuses and all(status == "not_found" for status in statuses):
            return "not_found"
        return "error"

    def _lookup_file(self, file: FileForEnrichment, provider: IntelligenceProvider) -> int:
        query_hash, query_hash_type = self._choose_query_hash(file, provider)
        lookup_id = self.repository.create_provider_lookup(file.id, provider.name, query_hash, query_hash_type)
        raw_response_path = None
        try:
            raw = provider.lookup(query_hash, query_hash_type)
            raw_response_path = self._store_raw_response(provider.name, query_hash, raw)
            intel = provider.normalize(raw, raw_response_path)
            self.repository.finish_provider_lookup(
                lookup_id,
                intel.provider_status,
                raw.get("_http_status"),
                intel.raw_response_path,
                intel.error_message,
            )
            if intel.provider_status == "success":
                self.repository.merge_intelligence(file.id, intel)
            return 0 if intel.provider_status in ("success", "not_found") else 1
        except ProviderAuthError as exc:
            self.disabled_providers.add(provider.name)
            self.repository.finish_provider_lookup(lookup_id, exc.status, exc.http_status, raw_response_path, exc.message)
            self.logger.error("provider disabled after authentication failure: %s", provider.name)
            return 1
        except ProviderRateLimitError as exc:
            self.disabled_providers.add(provider.name)
            self.repository.finish_provider_lookup(lookup_id, exc.status, exc.http_status, raw_response_path, exc.message)
            self.logger.warning("provider disabled after rate limit: %s", provider.name)
            return 1
        except ProviderError as exc:
            self.repository.finish_provider_lookup(lookup_id, exc.status, exc.http_status, raw_response_path, exc.message)
            return 1
        except Exception as exc:
            self.repository.finish_provider_lookup(lookup_id, "provider_error", None, raw_response_path, str(exc))
            return 1

    def _build_providers(self) -> list[IntelligenceProvider]:
        providers: list[IntelligenceProvider] = []
        for provider_name in self.config.enrichment.enabled_providers:
            if provider_name == "ctx_io":
                providers.append(CtxIoProvider(self.config.providers.ctx_io, self.config.enrichment))
        return providers

    @staticmethod
    def _choose_query_hash(file: FileForEnrichment, provider: IntelligenceProvider) -> tuple[str, str]:
        if file.sha256_hash and "sha256" in provider.supported_hash_types:
            return file.sha256_hash, "sha256"
        if file.md5_hash and "md5" in provider.supported_hash_types:
            return file.md5_hash, "md5"
        raise ProviderError("skipped", f"no supported hash for provider {provider.name}")

    def _store_raw_response(self, provider_name: str, query_hash: str, raw: dict[str, Any]) -> str | None:
        if not self.config.enrichment.store_raw_responses:
            return None
        directory = self.config.enrichment.raw_response_dir / provider_name
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{query_hash}.json"
        path.write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")
        return str(path)
