from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from yararuler.rules.update import _rule_inputs


def test_fingerprint_inputs_ignore_docs_but_follow_rule_includes(tmp_path: Path):
    source = SimpleNamespace(name="fixture", url="https://example.test/rules", ref="main", path=tmp_path)
    (tmp_path / "rule.yar").write_text('include "parts.inc"\n', encoding="utf-8")
    include = tmp_path / "parts.inc"
    include.write_text("rule One { condition: true }\n", encoding="utf-8")
    documentation = tmp_path / "README.md"
    documentation.write_text("first\n", encoding="utf-8")
    first = _rule_inputs([source])
    documentation.write_text("second\n", encoding="utf-8")
    assert _rule_inputs([source]) == first
    include.write_text("rule Two { condition: true }\n", encoding="utf-8")
    assert _rule_inputs([source]) != first
