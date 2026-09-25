"""Markdown report rendering and atomic report-slot publication for YARA scans."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from erecb_triage.ghintel.report import escape
from erecb_triage.report_provenance import items as provenance_items


def render_report(capture: dict, records: list[dict], metrics: dict[str, int], errors: list, *, cache_generation: str | None,
                  report_path: Path, base_dir: Path, generated_at: datetime) -> str:
    state = ("cache unavailable" if cache_generation is None else "successful match" if records else
             "partial scan" if errors else "successful no-match")
    lines = [f"# YARA Scan Report: {escape(capture['capture_name'])}", "", "## Summary", ""]
    summary = [("State", state), ("Original input", str(Path(capture["source_path"]).relative_to(base_dir))),
               ("Archive filename", capture["report_stem"]), ("Staged path", str(Path(capture["staged_path"]).relative_to(base_dir))),
               ("Cache generation", cache_generation), ("Files discovered", metrics.get("yara_files_discovered", 0)),
               ("Files selected", metrics.get("yara_files_selected", 0)), ("Files scanned", metrics.get("yara_files_scanned", 0)),
               ("Matched files", metrics.get("yara_files_matched", 0)), ("Rule matches", len(records)),
               ("Generated at", generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"))]
    summary.extend(provenance_items(capture))
    lines.extend(f"- {label}: {escape(value)}" for label, value in summary)
    lines.extend(["", "## Matched Files", "", "| File | SHA-256 | MD5 | Rules | Tags |", "| --- | --- | --- | --- | --- |"])
    grouped = {}
    for record in records: grouped.setdefault(record["display_path"], []).append(record)
    for path, matches in sorted(grouped.items()):
        lines.append("| " + " | ".join((escape(path), escape(matches[0]["sha256_hash"]), escape(matches[0]["md5_hash"]),
                                           str(len(matches)), escape(", ".join(sorted({tag for item in matches for tag in item["tags"]}))))) + " |")
    if not grouped: lines.append("| None |  |  | 0 |  |")
    lines.extend(["", "## Rule Details"])
    for record in records:
        provenance = record["provenance"]
        lines.extend(["", f"### {escape(record['display_path'])}: {escape(record['namespace'])}/{escape(record['rule'])}", "",
                      f"- Source: {escape(provenance['source'])}", f"- Rule path: {escape(provenance['path'])}",
                      f"- Source URL: {escape(provenance['url'])}", f"- Commit: {escape(provenance['commit'])}",
                      f"- Rule SHA-256: {escape(provenance['sha256'])}",
                      f"- Tags: {escape(', '.join(record['tags']))}"])
        if record.get("meta"): lines.append(f"- Metadata: {escape(', '.join(f'{key}={value}' for key, value in record['meta'].items()))}")
        if "strings" in record:
            locations = ", ".join(
                "{}@{}+{}".format(item["identifier"], item["offset"], item["length"])
                for item in record["strings"]
            )
            lines.append(f"- String locations: {escape(locations)}")
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {escape(error.code)}: {escape(error.message)}" for error in errors)
    if not errors: lines.append("None.")
    return "\n".join(lines) + "\n"


def publish_report(content: str, path: Path, authorize) -> None:
    if authorize() != path or not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("unsafe or unowned report path")
    temporary, directory = f".yara-{uuid4().hex}.tmp", os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory); created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content); handle.flush(); os.fsync(handle.fileno())
        if authorize() != path: raise ValueError("report reservation changed before publication")
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory); os.fsync(directory); created = False
    finally:
        try:
            if created: os.unlink(temporary, dir_fd=directory)
        finally: os.close(directory)
