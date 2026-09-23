from pathlib import Path

import pytest

from yararuler.errors import RuleBuildError
from yararuler.rules.compiler import namespace_for, validate_include_tree
from yararuler.rules.sync import redact_url, source_name_from_url


def test_namespace_is_stable_and_path_specific() -> None:
    first = namespace_for("source", "a/rule.yar")
    assert first == namespace_for("source", "a/rule.yar")
    assert first != namespace_for("source", "b/rule.yar")
    assert first.startswith("ns_")


def test_include_traversal_is_rejected(tmp_path: Path) -> None:
    root = tmp_path / "rules"
    root.mkdir()
    outside = tmp_path / "outside.yar"
    outside.write_text("rule outside { condition: true }", encoding="utf-8")
    top = root / "top.yar"
    top.write_text('include "../outside.yar"\n', encoding="utf-8")
    with pytest.raises(RuleBuildError, match="escapes"):
        validate_include_tree(top, root)


def test_include_cycle_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "a.yar").write_text('include "b.yar"\n', encoding="utf-8")
    (tmp_path / "b.yar").write_text('include "a.yar"\n', encoding="utf-8")
    with pytest.raises(RuleBuildError, match="cycle"):
        validate_include_tree(tmp_path / "a.yar", tmp_path)


def test_git_url_redaction_and_name() -> None:
    assert redact_url("https://user:secret@example.test/org/rules.git") == (
        "https://example.test/org/rules.git"
    )
    assert source_name_from_url("https://example.test/org/rules.git") == "rules"
