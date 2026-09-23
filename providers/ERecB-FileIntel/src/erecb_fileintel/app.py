from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .config import AppConfig, load_config
from .db.connection import connect
from .db.merge import MergeSummary, merge_databases
from .db.repository import Repository
from .enrichment.service import EnrichmentService
from .logging_setup import setup_logging
from .models import ScanSummary
from .scan.service import ScanService
from .watcher.service import WatchService


@dataclass
class AppContext:
    config: AppConfig
    repository: Repository
    enrichment_service: EnrichmentService
    scan_service: ScanService
    watch_service: WatchService


def build_context(config_path: str | Path) -> AppContext:
    config = load_config(config_path)
    setup_logging(config.log_level)
    conn = connect(config.database_path)
    repository = Repository(conn)
    repository.initialize_schema()
    enrichment_service = EnrichmentService(config, repository)
    scan_service = ScanService(config, repository, enrichment_service)
    watch_service = WatchService(config, repository, scan_service)
    return AppContext(config, repository, enrichment_service, scan_service, watch_service)


def init_db(config_path: str | Path) -> None:
    context = build_context(config_path)
    context.repository.initialize_schema()


def scan(config_path: str | Path, target_dir: str | Path) -> ScanSummary:
    context = build_context(config_path)
    return context.scan_service.run_manual_scan(Path(target_dir))


def watch(config_path: str | Path) -> None:
    context = build_context(config_path)
    context.watch_service.run()


def summary(config_path: str | Path) -> dict[str, int]:
    context = build_context(config_path)
    return context.repository.summary_counts()


def merge_db(
    source_path: str | Path,
    destination_path: str | Path,
    *,
    backup: bool = False,
    dry_run: bool = False,
    conflict_policy: str = "warn",
) -> MergeSummary:
    return merge_databases(
        source_path,
        destination_path,
        backup=backup,
        dry_run=dry_run,
        conflict_policy=conflict_policy,
    )
