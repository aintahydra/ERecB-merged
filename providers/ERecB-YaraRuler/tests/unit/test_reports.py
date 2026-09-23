import csv
import io
from datetime import UTC, datetime

from yararuler.models import (
    FileResult,
    RuleMatch,
    ScanMetadata,
    ScanSummary,
    StringMatch,
)
from yararuler.report.csv_writer import write_csv
from yararuler.report.json_writer import write_json


def summary(include_strings: bool = True) -> ScanSummary:
    now = datetime.now(UTC).isoformat()
    return ScanSummary(
        ScanMetadata(now, now, "/tmp/in", "generation", total_files_scanned=1),
        [
            FileResult(
                0,
                "in/a.bin",
                "/tmp/in/a.bin",
                "a" * 64,
                "b" * 32,
                [
                    RuleMatch(
                        "Known",
                        "source",
                        ["tag"],
                        {"author": "test"},
                        [StringMatch("$a", 3, 4)] if include_strings else None,
                    )
                ],
            )
        ],
        [],
    )


def test_json_has_versioned_top_level_contract() -> None:
    output = io.StringIO()
    write_json(summary(), output, pretty=False)
    assert '"schema_version":"1.0"' in output.getvalue()
    assert '"scan_metadata"' in output.getvalue()


def test_csv_has_one_row_per_rule_match() -> None:
    output = io.StringIO()
    write_csv(summary(), output)
    rows = list(csv.DictReader(io.StringIO(output.getvalue())))
    assert len(rows) == 1
    assert rows[0]["rule"] == "Known"
    assert rows[0]["strings"] == '[{"identifier":"$a","length":4,"offset":3}]'
