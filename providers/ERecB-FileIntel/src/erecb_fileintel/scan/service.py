from __future__ import annotations

import logging
from pathlib import Path

from erecb_fileintel.config import AppConfig
from erecb_fileintel.db.repository import Repository
from erecb_fileintel.enrichment.service import EnrichmentService
from erecb_fileintel.errors import FatalScanError, RecoverableScanError
from erecb_fileintel.models import FileObservation, ScanCounters, ScanSummary

from .classifier import FileClassifier
from .hashing import hash_file
from .walker import FileWalker


class ScanService:
    def __init__(
        self,
        config: AppConfig,
        repository: Repository,
        enrichment: EnrichmentService,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self.enrichment = enrichment
        self.classifier = FileClassifier()
        self.logger = logger or logging.getLogger(__name__)

    def run_manual_scan(self, target_dir: Path) -> ScanSummary:
        return self._run_scan("manual", target_dir)

    def run_watcher_scan(self, target_dir: Path) -> ScanSummary:
        return self._run_scan("watcher", target_dir)

    def _run_scan(self, mode: str, target_dir: Path) -> ScanSummary:
        root = target_dir.expanduser().resolve()
        if not root.exists() or not root.is_dir():
            raise FatalScanError(f"target directory does not exist or is not a directory: {root}")

        scan_job_id = self.repository.create_scan_job(mode, root)
        counters = ScanCounters()
        status = "succeeded"
        self.logger.info("scan job %s started: %s", scan_job_id, root)

        walker = FileWalker(self.config.scan.follow_symlinks, self.config.scan.max_file_size_bytes)
        try:
            for candidate in walker.walk(root):
                if isinstance(candidate, RecoverableScanError):
                    counters.error_count += 1
                    self.repository.record_scan_error(
                        scan_job_id,
                        None,
                        candidate.phase,
                        candidate.type,
                        candidate.message,
                    )
                    continue

                counters.files_seen += 1
                try:
                    classification = self.classifier.classify(candidate.path)
                    if not classification.is_executable:
                        continue

                    hash_result = hash_file(candidate.path, self.config.scan.hash_block_size_bytes)
                    observation = FileObservation(
                        scan_job_id=scan_job_id,
                        file_path=candidate.path,
                        file_name=candidate.name,
                        magic=classification.magic,
                        sha256_hash=hash_result.sha256_hash,
                        md5_hash=hash_result.md5_hash,
                    )
                    self.repository.upsert_local_observation(observation)
                    counters.executables_found += 1
                except Exception as exc:
                    counters.error_count += 1
                    self.repository.record_scan_error(
                        scan_job_id,
                        candidate.path,
                        "scan",
                        exc.__class__.__name__,
                        str(exc),
                    )

            enrichment_errors = self.enrichment.enrich_scan_job(scan_job_id)
            counters.error_count += enrichment_errors
            if counters.error_count:
                status = "partial"
            return ScanSummary(scan_job_id, status, counters.files_seen, counters.executables_found, counters.error_count)
        except Exception:
            status = "failed"
            raise
        finally:
            self.repository.finish_scan_job(scan_job_id, status, counters)
            self.logger.info(
                "scan job %s finished: status=%s files=%s executables=%s errors=%s",
                scan_job_id,
                status,
                counters.files_seen,
                counters.executables_found,
                counters.error_count,
            )
