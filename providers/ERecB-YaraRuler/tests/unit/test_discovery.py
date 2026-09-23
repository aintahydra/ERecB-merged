from pathlib import Path

from yararuler.scan.discovery import FileDiscoverer


def test_discovery_is_deterministic_and_skips_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "in"
    target.mkdir()
    (target / "b.bin").write_bytes(b"b")
    (target / "a.bin").write_bytes(b"a")
    (target / "link.bin").symlink_to(target / "a.bin")
    paths = [item.path.name for item in FileDiscoverer(target).iter_files()]
    assert paths == ["a.bin", "b.bin"]


def test_discovery_excludes_report_path(tmp_path: Path) -> None:
    target = tmp_path / "in"
    target.mkdir()
    report = target / "report.json"
    report.write_text("old", encoding="utf-8")
    (target / "sample.bin").write_bytes(b"sample")
    paths = [
        item.path.name for item in FileDiscoverer(target, excluded_paths={report}).iter_files()
    ]
    assert paths == ["sample.bin"]
