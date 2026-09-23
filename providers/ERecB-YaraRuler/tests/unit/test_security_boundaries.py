from pathlib import Path

import pytest
from pydantic import ValidationError

from yararuler.config import RuleSource
from yararuler.errors import CacheError
from yararuler.rules.cache import load_active_cache


@pytest.mark.parametrize("ref", ["--upload-pack=bad", "a..b", "a b", "a@{b", "a//b"])
def test_unsafe_git_refs_are_rejected(ref: str) -> None:
    with pytest.raises(ValidationError, match="safe Git ref"):
        RuleSource(name="source", url="https://example.invalid/rules.git", ref=ref)


def test_active_cache_pointer_cannot_escape_generation_directory(tmp_path: Path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "active").write_text("../../outside\n", encoding="utf-8")
    with pytest.raises(CacheError, match="invalid active generation"):
        load_active_cache(cache)
