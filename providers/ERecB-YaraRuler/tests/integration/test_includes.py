from pathlib import Path

import pytest

pytest.importorskip("yara")

from yararuler.models import SyncedSource
from yararuler.rules.compiler import compile_aggregate, validate_sources


def test_relative_includes_compile_in_individual_and_aggregate_phases(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "shared.yar").write_text(
        "private rule Shared { condition: true }\n", encoding="utf-8"
    )
    (source_root / "top.yar").write_text(
        'include "shared.yar"\nrule Top { condition: Shared }\n', encoding="utf-8"
    )
    source = SyncedSource(
        name="fixture",
        url="file:///fixture",
        ref=None,
        commit="abc",
        path=source_root,
    )

    accepted, rejected = validate_sources([source])
    assert rejected == []
    assert {item.path for item in accepted} == {"shared.yar", "top.yar"}

    output = tmp_path / "rules.yac"
    compile_aggregate(accepted, output)
    assert output.is_file()
