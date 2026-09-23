"""Bounded, durable operational logging for the command-line watcher."""

from __future__ import annotations

import logging
import time
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from erecb_triage.config import resolve_path


def configure_operational_logging(config: dict[str, Any], base_dir: Path) -> Path | None:
    """Configure terminal plus rotating-file logs; retain terminal logs on file failure."""
    settings = config["logging"]
    level = getattr(logging, settings["level"])
    formatter = logging.Formatter(
        "%(asctime)sZ %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    formatter.converter = time.gmtime
    console = logging.StreamHandler()
    console.setFormatter(formatter)
    log_path = resolve_path(base_dir, settings["file_path"])
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path, maxBytes=settings["max_bytes"], backupCount=settings["backup_count"], encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
    except OSError as exc:
        logging.basicConfig(level=level, handlers=[console], force=True)
        logging.getLogger("erecb_triage").warning(
            "operational log file unavailable path=%s error=%s; continuing with terminal logging only",
            log_path, exc,
        )
        return None
    logging.basicConfig(level=level, handlers=[console, file_handler], force=True)
    logging.getLogger("erecb_triage").info(
        "operational logging initialized path=%s max_bytes=%d backup_count=%d",
        log_path, settings["max_bytes"], settings["backup_count"],
    )
    return log_path
