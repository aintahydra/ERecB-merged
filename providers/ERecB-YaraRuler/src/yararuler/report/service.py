from __future__ import annotations

import contextlib
import json
import logging
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from yararuler.errors import ReportError
from yararuler.models import ScanSummary
from yararuler.report.csv_writer import write_csv
from yararuler.report.json_writer import write_json

LOGGER = logging.getLogger(__name__)


def _atomic_text_write(path: Path, writer: Callable[[TextIO], None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            errors="replace",
            newline="",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as handle:
            temporary_name = handle.name
            writer(handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception as exc:
        if temporary_name:
            with contextlib.suppress(OSError):
                Path(temporary_name).unlink(missing_ok=True)
        raise ReportError(f"cannot write report {path}: {exc}") from exc


def _metadata_document(summary: ScanSummary) -> dict[str, object]:
    document = summary.to_dict()
    return {
        "schema_version": document["schema_version"],
        "scan_metadata": document["scan_metadata"],
        "errors": document["errors"],
    }


def _write_metadata(summary: ScanSummary, handle: TextIO, pretty: bool) -> None:
    json.dump(
        _metadata_document(summary),
        handle,
        ensure_ascii=False,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
    )
    handle.write("\n")


class ReportService:
    def write(self, summary: ScanSummary, *, output: str, format: str, pretty_json: bool) -> None:
        if format not in {"json", "csv"}:
            raise ReportError(f"unsupported report format: {format}")
        if output == "-":
            if format == "json":
                write_json(summary, sys.stdout, pretty=pretty_json)
            else:
                write_csv(summary, sys.stdout)
                LOGGER.info(
                    "CSV stdout report: scanned=%d matched_files=%d matches=%d errors=%d",
                    summary.metadata.total_files_scanned,
                    summary.metadata.total_files_matched,
                    summary.metadata.total_matches,
                    summary.metadata.total_errors,
                )
            return
        path = Path(output).resolve()
        if format == "json":
            _atomic_text_write(path, lambda handle: write_json(summary, handle, pretty=pretty_json))
            return
        _atomic_text_write(path, lambda handle: write_csv(summary, handle))
        _atomic_text_write(
            Path(f"{path}.metadata.json"),
            lambda handle: _write_metadata(summary, handle, pretty_json),
        )
