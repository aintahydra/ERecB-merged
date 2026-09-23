from pathlib import Path

from yararuler.errors import RuleBuildError
from yararuler.models import RuleEntry
from yararuler.rules import aggregate


def entry(tmp_path: Path, name: str) -> RuleEntry:
    path = tmp_path / name
    path.write_text("rule fixture { condition: true }", encoding="utf-8")
    return RuleEntry("source", "url", "commit", name, path, "digest", f"ns_{name}")


def test_aggregate_failure_isolated_without_dropping_good_entries(tmp_path, monkeypatch) -> None:
    good = entry(tmp_path, "good.yar")
    bad = entry(tmp_path, "bad.yar")
    calls = []

    def fake_compile(entries, output):
        calls.append([item.path for item in entries])
        if bad in entries and good in entries:
            raise RuleBuildError("simulated interaction")
        output.write_bytes(b"cache")

    monkeypatch.setattr(aggregate, "compile_aggregate", fake_compile)
    accepted, rejected = aggregate.compile_with_isolation([good, bad], tmp_path / "rules.yac")
    assert accepted == [good]
    assert [item.path for item in rejected] == ["bad.yar"]
    assert rejected[0].phase == "aggregate_compile"
    assert calls
