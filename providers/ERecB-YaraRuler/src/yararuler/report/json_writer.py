from __future__ import annotations

import json
from typing import TextIO

from yararuler.models import ScanSummary


def write_json(summary: ScanSummary, destination: TextIO, *, pretty: bool) -> None:
    json.dump(
        summary.to_dict(),
        destination,
        ensure_ascii=False,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        sort_keys=False,
    )
    destination.write("\n")
