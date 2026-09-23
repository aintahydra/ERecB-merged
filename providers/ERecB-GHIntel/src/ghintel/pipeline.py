"""Stage 1 local-only orchestration."""

from __future__ import annotations

from .config import ResolvedConfig
from .database import database, initialize, record_discovery
from .discovery import discover_repositories
from .sources import capture_sources


def run_discovery(config: ResolvedConfig) -> tuple[int, int]:
    """Discover, capture local documentary sources, and persist one run."""
    initialize(config.db_path)
    locations = discover_repositories(config.input_dir)
    sources = {
        location.path: capture_sources(
            location.path,
            max_document_bytes=config.config.scan.max_document_bytes,
            max_source_bytes=config.config.scan.max_source_bytes_per_repo,
        )
        for location in locations
    }
    with database(config.db_path) as connection:
        run_id = record_discovery(connection, config.input_dir, locations, sources)
    return run_id, len(locations)
