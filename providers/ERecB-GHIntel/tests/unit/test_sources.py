from pathlib import Path

from ghintel.sources import capture_sources


def test_plain_readme_is_original_and_language_readme_is_translation(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("original", encoding="utf-8")
    (tmp_path / "README_ko.md").write_text("한국어 번역 문서", encoding="utf-8")
    (tmp_path / "README_zh-CN.md").write_text("中文翻译文档", encoding="utf-8")
    captured = capture_sources(tmp_path, max_document_bytes=1000, max_source_bytes=1000)
    translations = {str(item.path): item.translation for item in captured}
    assert translations == {"README.md": False, "README_ko.md": True, "README_zh-CN.md": True}
