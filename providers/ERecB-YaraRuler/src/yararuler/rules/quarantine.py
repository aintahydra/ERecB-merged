from __future__ import annotations

import json
import shutil
from pathlib import Path

from yararuler.models import RejectedRule
from yararuler.rules.compiler import yara_version

MAX_QUARANTINE_FILE_BYTES = 1024 * 1024
MAX_QUARANTINE_TOTAL_BYTES = 50 * 1024 * 1024


def stage_quarantine(rejected: list[RejectedRule], staging: Path, timestamp: str) -> None:
    staging.mkdir(parents=True, exist_ok=False)
    copied = 0
    for item in rejected:
        destination = staging / item.source / item.path
        destination.parent.mkdir(parents=True, exist_ok=True)
        copy_size = 0
        truncated = False
        try:
            size = item.absolute_path.stat().st_size
            if size <= MAX_QUARANTINE_FILE_BYTES and copied + size <= MAX_QUARANTINE_TOTAL_BYTES:
                shutil.copyfile(item.absolute_path, destination)
                copied += size
                copy_size = size
            else:
                truncated = True
        except OSError:
            truncated = True
        sidecar = Path(f"{destination}.error.json")
        sidecar.write_text(
            json.dumps(
                {
                    "source": item.source,
                    "source_url": item.source_url,
                    "commit": item.commit,
                    "original_path": item.path,
                    "sha256": item.sha256,
                    "yara_version": yara_version(),
                    "phase": item.phase,
                    "error_class": item.error_class,
                    "diagnostic": item.diagnostic,
                    "timestamp": timestamp,
                    "copied_bytes": copy_size,
                    "copy_truncated": truncated,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
