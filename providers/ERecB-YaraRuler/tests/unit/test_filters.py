from pathlib import Path

import pytest

from yararuler.errors import ConfigurationError
from yararuler.models import Candidate
from yararuler.scan.filters import CandidateFilter


def candidate(path: Path, label: str | None = None) -> Candidate:
    return Candidate(0, path, label or path.name)


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("no-extension", b"MZpayload"),
        ("sample", b"\x7fELFpayload"),
        ("tool", b"#!/usr/bin/env python\nprint('x')"),
        ("run.PS1", b"not really executable"),
        ("library.DLL", b"data"),
    ],
)
def test_exec_filter_recognizes_heuristics(tmp_path: Path, name: str, content: bytes) -> None:
    path = tmp_path / name
    path.write_bytes(content)
    assert CandidateFilter(selector="exec-only").accepts(candidate(path))


def test_filter_families_are_anded_and_repeats_are_ored(tmp_path: Path) -> None:
    path = tmp_path / "sample_payload.bin"
    path.write_bytes(b"content")
    filter_ = CandidateFilter(
        selector="all",
        globs=["*.exe", "*.bin"],
        regexes=[r"^other/", r"^in/release/"],
    )
    assert filter_.accepts(candidate(path, "in/release/sample_payload.bin"))
    assert not filter_.accepts(candidate(path, "in/staging/sample_payload.bin"))


def test_invalid_regex_fails_before_scan() -> None:
    with pytest.raises(ConfigurationError, match="regular expression"):
        CandidateFilter(selector="all", regexes=["["])
