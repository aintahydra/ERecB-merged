from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

pytest.importorskip("yara")

from yararuler.config import load_config
from yararuler.rules.update import RuleUpdateService
from yararuler.scan.service import ScanService


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )


def test_update_quarantine_cache_and_scan(tmp_path: Path) -> None:
    upstream = tmp_path / "upstream"
    upstream.mkdir()
    git(upstream, "init")
    git(upstream, "config", "user.email", "tests@example.invalid")
    git(upstream, "config", "user.name", "YaraRuler Tests")
    (upstream / "valid.yar").write_text(
        """
rule Known_Test : fixture {
  meta:
    author = "tests"
    description = "harmless integration fixture"
  strings:
    $needle = "MALWARE_TEST"
  condition:
    $needle
}
""",
        encoding="utf-8",
    )
    (upstream / "invalid.yar").write_text(
        "rule Broken { condition: this is not valid yara }\n", encoding="utf-8"
    )
    git(upstream, "add", "valid.yar", "invalid.yar")
    git(upstream, "commit", "-m", "fixtures")

    target = tmp_path / "in"
    target.mkdir()
    sample = target / "sample.bin"
    sample.write_bytes(b"prefix MALWARE_TEST suffix")
    (target / "ignored.txt").write_text("nothing to see", encoding="utf-8")

    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f"""
[paths]
rules_dir = "state/rules"
target_dir = "in"
[rules]
cache_dir = "state/cache"
quarantine_dir = "state/quarantine"
[[rules.sources]]
name = "fixture"
url = {str(upstream)!r}
[scan]
threads = 1
timeout_seconds = 10
default_selector = "all"
[report]
output = "report.json"
""",
        encoding="utf-8",
    )
    config = load_config(config_path)

    update = RuleUpdateService().update(config)
    assert update.accepted == 1
    assert update.quarantined == 1
    assert update.cache_path.is_file()
    assert (config.rules.cache_dir / "active").read_text(
        encoding="utf-8"
    ).strip() == update.generation
    manifest = json.loads(
        (config.rules.cache_dir / "generations" / update.generation / "manifest.json").read_text(encoding="utf-8")
    )
    assert manifest["schema_version"] == 1
    assert manifest["generation_id"] == update.generation
    assert isinstance(manifest["platform"], str) and manifest["platform"]
    assert isinstance(manifest["machine"], str) and manifest["machine"]
    assert set(manifest["runtime"]) == {"yara_version", "yara_python_version"}
    assert all(manifest["runtime"].values())
    assert manifest["artifact"]["filename"] == "rules.yac"
    assert manifest["artifact"]["size"] == update.cache_path.stat().st_size
    assert len(manifest["artifact"]["sha256"]) == 64
    assert len(manifest["accepted_rules"]) == 1
    accepted_rule = manifest["accepted_rules"][0]
    assert set(accepted_rule) == {"source", "url", "commit", "path", "sha256", "namespace"}
    assert accepted_rule["source"] == "fixture"
    assert accepted_rule["url"] == str(upstream)
    assert accepted_rule["commit"] == manifest["sources"][0]["commit"]
    assert accepted_rule["path"] == "valid.yar"
    assert len(accepted_rule["sha256"]) == 64
    assert accepted_rule["namespace"]
    assert (config.rules.quarantine_dir / "fixture/invalid.yar.error.json").is_file()

    single = ScanService().scan(
        config,
        target_dir=target,
        selector="all",
        globs=["*.bin"],
        regexes=[],
        threads=1,
        timeout_seconds=10,
        include_strings=True,
    )
    assert single.metadata.total_files_discovered == 2
    assert single.metadata.total_files_selected == 1
    assert single.metadata.total_files_scanned == 1
    assert single.metadata.total_files_matched == 1
    assert single.metadata.total_matches == 1
    assert single.errors == []
    result = single.results[0]
    assert result.file_path == "in/sample.bin"
    assert len(result.sha256) == 64
    assert len(result.md5) == 32
    assert result.matches[0].rule == "Known_Test"
    assert result.matches[0].tags == ["fixture"]
    assert result.matches[0].meta["author"] == "tests"
    assert result.matches[0].strings[0].identifier == "$needle"

    parallel = ScanService().scan(
        config,
        target_dir=target,
        selector="all",
        globs=["*.bin"],
        regexes=[],
        threads=2,
        timeout_seconds=10,
        include_strings=True,
    )
    assert parallel.results == single.results
    assert parallel.errors == single.errors
    assert parallel.metadata.total_files_scanned == single.metadata.total_files_scanned
    assert parallel.metadata.total_matches == single.metadata.total_matches
