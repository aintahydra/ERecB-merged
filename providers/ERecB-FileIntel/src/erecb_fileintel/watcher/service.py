from __future__ import annotations

import logging
import time

from erecb_fileintel.config import AppConfig
from erecb_fileintel.db.repository import Repository
from erecb_fileintel.scan.service import ScanService

from .detector import detect_watch_targets


class WatchService:
    def __init__(
        self,
        config: AppConfig,
        repository: Repository,
        scan_service: ScanService,
        logger: logging.Logger | None = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self.scan_service = scan_service
        self.logger = logger or logging.getLogger(__name__)

    def run(self) -> None:
        input_dir = self.config.input_dir
        known = self.repository.list_known_watch_directories(input_dir, self.config.watch_depth)
        self.logger.info("watching %s at depth %s", input_dir, self.config.watch_depth)
        while True:
            current = detect_watch_targets(input_dir, self.config.watch_depth)
            for relative_path in sorted(current - known):
                absolute_path = (input_dir / relative_path).resolve()
                watch_id = self.repository.insert_watch_directory(
                    input_dir,
                    relative_path,
                    absolute_path,
                    self.config.watch_depth,
                )
                self.repository.update_watch_directory_status(watch_id, "scanning", None)
                summary = self.scan_service.run_watcher_scan(absolute_path)
                final_status = "scanned" if summary.status in ("succeeded", "partial") else "failed"
                self.repository.update_watch_directory_status(watch_id, final_status, summary.scan_job_id)
                known.add(relative_path)
            time.sleep(self.config.watch_interval_seconds)

