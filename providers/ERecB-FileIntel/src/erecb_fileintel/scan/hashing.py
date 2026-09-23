from __future__ import annotations

import hashlib
from pathlib import Path

from erecb_fileintel.models import HashResult


def hash_file(path: Path, block_size: int) -> HashResult:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5(usedforsecurity=False)
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(block_size)
            if not chunk:
                break
            sha256.update(chunk)
            md5.update(chunk)
    return HashResult(sha256.hexdigest(), md5.hexdigest())

