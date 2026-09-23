from __future__ import annotations

import csv
import json
from dataclasses import asdict
from typing import TextIO

from yararuler.models import ScanSummary

COLUMNS = (
    "file_path",
    "absolute_path",
    "sha256",
    "md5",
    "rule",
    "namespace",
    "tags",
    "meta",
    "strings",
)


def compact_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def write_csv(summary: ScanSummary, destination: TextIO) -> None:
    writer = csv.DictWriter(destination, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    for result in summary.results:
        for match in result.matches:
            writer.writerow(
                {
                    "file_path": result.file_path,
                    "absolute_path": result.absolute_path,
                    "sha256": result.sha256,
                    "md5": result.md5,
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "tags": compact_json(match.tags),
                    "meta": compact_json(match.meta),
                    "strings": compact_json(
                        [asdict(item) for item in match.strings]
                        if match.strings is not None
                        else []
                    ),
                }
            )
