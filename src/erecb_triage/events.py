from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4


@dataclass(frozen=True)
class WatchEvent:
    id: str
    kind: str
    root_path: Path
    path: Path
    relative_path: Path
    is_directory: bool
    observed_at: datetime

    @property
    def capture_root(self) -> Path:
        return self.root_path / self.relative_path.parts[0]

    @property
    def source_name(self) -> str:
        return self.path.name

    @classmethod
    def added(cls, root_path: Path, path: Path) -> "WatchEvent":
        root = root_path.resolve()
        event_path = path.absolute()
        if event_path.is_symlink():
            raise ValueError("symlink capture inputs are not accepted")
        return cls(
            id=f"evt-{uuid4()}",
            kind="added",
            root_path=root,
            path=event_path,
            relative_path=event_path.relative_to(root),
            is_directory=event_path.is_dir(),
            observed_at=datetime.now(timezone.utc),
        )
