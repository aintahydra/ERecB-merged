from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from erecb_ipintel.config import ExtractionConfig
from erecb_ipintel.discovery import recognized_directories
from erecb_ipintel.scanner import scan_directory


class DiscoveryTests(unittest.TestCase):
    def test_recognized_directories_depth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a" / "b").mkdir(parents=True)
            (root / "a" / "c").mkdir(parents=True)
            (root / "d").mkdir()
            self.assertEqual([p.name for p in recognized_directories(root, 1)], ["a", "d"])
            self.assertEqual([str(p.relative_to(root)) for p in recognized_directories(root, 2)], ["a/b", "a/c"])

    def test_scan_directory_reports_directory_progress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a" / "b").mkdir(parents=True)
            events: list[tuple[str, int, int]] = []

            scan_directory(
                root,
                root,
                ExtractionConfig(),
                progress=lambda stage, completed, total: events.append((stage, completed, total)),
            )

        self.assertEqual(events[0], ("scan directories", 0, 3))
        self.assertEqual(events[-1], ("scan directories", 3, 3))


if __name__ == "__main__":
    unittest.main()
