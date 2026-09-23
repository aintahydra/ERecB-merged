"""Safe Markdown rendering and atomic owned GHIntel report publication."""
from __future__ import annotations

import html
import os
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_from_bytes
from uuid import uuid4


def escape(value) -> str:
    text = "not recorded" if value is None else str(value)
    text = "".join(f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C")
                   or unicodedata.category(char) in {"Zl", "Zp"} else char for char in text)
    return html.escape("".join("\\" + char if char in "\\`*_{}[]()#+-.!|~" else char for char in text), quote=True)


def _display(path: str | Path, base: Path) -> str:
    path = Path(path)
    return str(path.relative_to(base)) if path.is_relative_to(base) else str(path)


def source_link(path: str, base: Path, report: Path) -> str:
    target = os.path.relpath(path, report.parent)
    return f"[{escape(_display(path, base))}](<{quote_from_bytes(os.fsencode(target), safe='/.')}>)"


def render_report(capture: dict, records: list[dict], metrics: dict[str, int], errors: list, *, base_dir: Path,
                  report_path: Path, database_path: Path, database_availability: str, generated_at: datetime) -> str:
    observations = {item["identity_key"]: [] for item in records if item["type"] == "github_repository_observation"}
    lookups, hits = {}, {}
    for item in records:
        if item["type"] == "github_repository_observation": observations[item["identity_key"]].append(item)
        elif item["type"] == "github_intel_lookup": lookups[item["identity_key"]] = item
        elif item["type"] == "github_intel_hit": hits[item["identity_key"]] = item
    lines = [f"# GitHub Intelligence Report: {escape(capture['capture_name'])}", "", "## Summary", ""]
    summary = [("Original input", _display(capture["source_path"], base_dir)), ("Archive filename", capture["report_stem"]),
               ("Source SHA-256", capture.get("source_sha256")), ("Staged path", _display(capture["staged_path"], base_dir)),
               ("Database path", _display(database_path, base_dir)), ("Database availability", database_availability),
               ("Unique repositories", metrics["ghintel_unique_repositories"]), ("Source event ID", capture["source_event_id"]),
               ("Pipeline run ID", capture["pipeline_run_id"]),
               ("Generated at", generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"))]
    lines.extend(f"- {label}: {escape(value)}" for label, value in summary)

    def table(title, headers, rows):
        lines.extend(["", f"## {title}", "", "| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"])
        lines.extend("| " + " | ".join(row) + " |" for row in rows)

    ordered = sorted(lookups)
    table("Repositories With Local Intelligence", ["Repository", "Status", "Purpose", "Sources"], [
        [f"[{escape(hits[key]['canonical_url'])}](<{hits[key]['canonical_url']}>)", escape(hits[key]["information_status"]),
         escape(hits[key].get("purpose")), "; ".join(source_link(item["source_path"], base_dir, report_path) for item in observations[key])]
        for key in ordered if key in hits])
    table("Repositories Without Local Intelligence", ["Repository", "Sources"], [
        [escape(observations[key][0]["canonical_url"]), "; ".join(source_link(item["source_path"], base_dir, report_path) for item in observations[key])]
        for key in ordered if lookups[key]["status"] == "miss"])
    table("Intelligence Lookup Incomplete", ["Repository", "Status", "Error"], [
        [escape(observations[key][0]["canonical_url"]), escape(lookups[key]["status"]), escape(lookups[key].get("error_code"))]
        for key in ordered if lookups[key]["status"] in {"unavailable", "error"}])
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {escape(error.code)}: {escape(error.message)}" for error in errors)
    if not errors: lines.append("None.")
    lines.extend(["", "## Details"])
    for key in ordered:
        if key not in hits: continue
        card = hits[key]
        lines.extend(["", f"### {escape(card['canonical_url'])}", "", f"- Information status: {escape(card['information_status'])}",
                      f"- Purpose: {escape(card.get('purpose'))}", f"- Tool types: {escape(', '.join(card.get('tool_types', [])))}",
                      f"- Capabilities: {escape(', '.join(card.get('capabilities', [])))}",
                      f"- Intended uses: {escape(', '.join(card.get('intended_uses', [])))}",
                      f"- GitHub owner: {escape(card.get('owner_login') or card.get('owner'))} ({escape(card.get('owner_type'))})",
                      "- Current source paths:"])
        lines.extend(f"  - {source_link(item['source_path'], base_dir, report_path)}" for item in observations[key])
    return "\n".join(lines) + "\n"


def publish_report(content: str, path: Path, authorize) -> None:
    if authorize() != path or not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("unsafe or unowned report path")
    temporary, directory = f".ghintel-{uuid4().hex}.tmp", os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = False
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
        created = True
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content); handle.flush(); os.fsync(handle.fileno())
        if authorize() != path: raise ValueError("report reservation changed before publication")
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory); os.fsync(directory); created = False
    finally:
        try:
            if created: os.unlink(temporary, dir_fd=directory)
        finally: os.close(directory)
