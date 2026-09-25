"""Escaped Markdown reports and ownership-checked atomic publication."""

from __future__ import annotations

import html
import os
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_from_bytes
from uuid import uuid4
from erecb_triage.report_provenance import items as provenance_items


def escape(value) -> str:
    """Keep hostile metadata on one line and inert in Markdown and HTML."""
    text = "not recorded" if value is None else str(value)
    text = "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C")
        or unicodedata.category(char) in {"Zl", "Zp"} else char
        for char in text
    )
    text = "".join("\\" + char if char in "\\`*_{}[]()#+-.!|~" else char for char in text)
    return html.escape(text, quote=True)


def _display(path, base_dir):
    path = Path(path)
    return str(path.relative_to(base_dir)) if path.is_relative_to(base_dir) else str(path)


def source_link(path, base_dir: Path, report_path: Path) -> str:
    path = Path(path)
    # URL resolution is relative to the report, not the display label's base.
    target = os.path.relpath(path, report_path.parent)
    return f"[{escape(_display(path, base_dir))}](<{quote_from_bytes(os.fsencode(target), safe='/.')}>)"


def render_report(capture, records, metrics, errors, *, base_dir: Path, report_path: Path,
                  classification_availability: str, database_path: Path, database_availability: str,
                  generated_at: datetime) -> str:
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("report generation time must have a timezone")
    observations, lookups, hits, ambiguities = {}, {}, {}, {}
    for record in records:
        sha = record["sha256_hash"]
        if record["type"] == "file_observation":
            observations.setdefault(sha, []).append(record)
        elif record["type"] == "file_intel_lookup":
            lookups[sha] = record
        elif record["type"] == "file_intel_hit":
            hits[sha] = record
        elif record["type"] == "file_intel_ambiguity":
            ambiguities[sha] = record
    for items in observations.values():
        items.sort(key=lambda item: item["source_path"])
    ordered = sorted(lookups, key=lambda sha: (
        {"yes": 0, "unknown": 1, "no": 2}.get(hits.get(sha, {}).get("malicious"), 3),
        sha, observations[sha][0]["source_path"],
    ))

    def links(sha):
        return "; ".join(source_link(item["source_path"], base_dir, report_path)
                         for item in observations[sha])

    def attributed(items, key):
        return "; ".join(f"{escape(item[key])} ({escape(item['source'])})" for item in items) or "None"

    def paths_with(status):
        return sum(len(observations[sha]) for sha in ordered if lookups[sha]["status"] == status)

    lines = [f"# File Intelligence Report: {escape(capture['capture_name'])}", "", "## Summary", ""]
    summary = [
        ("Original input", _display(capture["source_path"], base_dir)),
        ("Archive filename", capture["report_stem"]),
        ("Source SHA-256", capture.get("source_sha256")),
        ("Staging started at", capture["staging_started_at"]),
        ("Staged path", _display(capture["staged_path"], base_dir)),
        ("Database path", _display(database_path, base_dir)),
        ("Source event ID", capture["source_event_id"]), ("Pipeline run ID", capture["pipeline_run_id"]),
        ("Files scanned", metrics["fileintel_files_scanned"]),
        ("Files skipped", metrics["fileintel_files_skipped"]),
        ("Executables found", metrics["fileintel_executables_found"]),
        ("Successfully hashed paths" if capture.get("fileintel_selector") == "all" else
         "Successfully hashed executable paths", metrics["fileintel_observations"]),
        ("Executables with local intelligence", paths_with("hit")),
        ("Executables without local intelligence", paths_with("miss")),
        ("Unique hashes" if capture.get("fileintel_selector") == "all" else
         "Unique executable hashes", metrics["fileintel_unique_hashes"]),
        ("Lookup hits / misses / ambiguities / unavailable / errors", " / ".join(str(metrics[key]) for key in (
            "fileintel_lookup_hits", "fileintel_lookup_misses", "fileintel_lookup_ambiguities",
            "fileintel_lookup_unavailable", "fileintel_lookup_errors",
        ))),
        ("Classification availability", classification_availability),
        ("Database availability", database_availability),
        ("Generated at", generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")),
    ]
    summary.extend(provenance_items(capture, "file_retriever"))
    lines.extend(f"- {label}: {escape(value)}" for label, value in summary)

    def table(title, headers, rows):
        lines.extend(["", f"## {title}", "", "| " + " | ".join(headers) + " |",
                      "| " + " | ".join("---" for _ in headers) + " |"])
        lines.extend("| " + " | ".join(row) + " |" for row in rows)

    table("Executables With Local Intelligence", ["SHA-256", "MD5", "Match", "Malicious", "Tags", "Names", "Sources"], [
        [sha, lookups[sha]["md5_hash"], "SHA-256" if hits[sha]["match_type"] == "sha256" else "MD5 (weak)",
         escape(hits[sha]["malicious"]), attributed(hits[sha]["tags"], "tag"),
         attributed(hits[sha]["file_names"], "file_name"), links(sha)]
        for sha in ordered if sha in hits
    ])
    table("Executables Without Local Intelligence", ["SHA-256", "MD5", "Magic", "Sources"], [
        [sha, lookups[sha]["md5_hash"], "; ".join(sorted({escape(item["magic"]) for item in observations[sha]})), links(sha)]
        for sha in ordered if lookups[sha]["status"] == "miss"
    ])
    table("Ambiguous MD5 Matches", ["MD5", "Observed SHA-256", "Candidate DB Rows", "Reason", "Sources"], [
        [lookups[sha]["md5_hash"], sha, ", ".join(map(str, ambiguities[sha]["candidate_file_entity_ids"])),
         escape(ambiguities[sha]["reason"]), links(sha)]
        for sha in ordered if sha in ambiguities
    ])
    table("Intelligence Lookup Incomplete", ["SHA-256", "MD5", "Lookup Status", "Error Code", "Sources"], [
        [sha, lookups[sha]["md5_hash"], escape(lookups[sha]["status"]), escape(lookups[sha]["error_code"]), links(sha)]
        for sha in ordered if lookups[sha]["status"] in {"unavailable", "error"}
    ])
    lines.extend(["", "## Warnings", ""])
    lines.extend(f"- {escape(error.code)}: {escape(_display(error.path, base_dir))}: {escape(error.message)}"
                 for error in sorted(errors, key=lambda item: (str(item.path), item.code, item.message)))
    if not errors:
        lines.append("None.")
    lines.extend(["", "## Details"])
    for sha in ordered:
        lookup, hit = lookups[sha], hits.get(sha)
        lines.extend(["", f"### {sha}", "", f"- MD5: {lookup['md5_hash']}",
                      f"- Lookup status: {escape(lookup['status'])}"])
        if lookup["error_code"]:
            lines.append(f"- Error code: {escape(lookup['error_code'])}")
        if sha in ambiguities:
            lines.append(f"- Ambiguity reason: {escape(ambiguities[sha]['reason'])}")
        lines.append("- Current source paths:")
        for item in observations[sha]:
            lines.append(f"  - {source_link(item['source_path'], base_dir, report_path)}; "
                         f"size={item['size_bytes']}; magic={escape(item['magic'])}; "
                         f"classification reason={escape(item['classification_reason'])}")
        if not hit:
            continue
        for label, key in (
            ("Match strength", "match_type"), ("DB file entity ID", "file_entity_id"),
            ("DB SHA-256", "db_sha256_hash"), ("DB MD5", "db_md5_hash"),
            ("Malicious", "malicious"), ("DB magic", "magic"),
            ("Created at", "created_at"), ("Updated at", "updated_at"),
        ):
            value = "md5 (weak)" if key == "match_type" and hit[key] == "md5" else hit[key]
            lines.append(f"- {label}: {escape(value)}")
        for label, key in (("Known names", "file_names"), ("Tags", "tags"),
                           ("Historical observations (not current evidence)", "historical_observations"),
                           ("Provider lookups", "provider_lookups")):
            lines.append(f"- {label}:")
            for child in hit[key]:
                lines.append("  - " + "; ".join(f"{escape(k)}={escape(v)}" for k, v in child.items()))
            if not hit[key]:
                lines.append("  - None.")
    return "\n".join(lines) + "\n"


def publish_report(content: str, path: Path, authorize) -> None:
    """Publish through an anchored output directory after rechecking ownership."""
    if authorize() != path or not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("unsafe or unowned report path")
    temporary = f".fileintel-{uuid4().hex}.tmp"
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
        created = True
        try:
            handle = os.fdopen(fd, "w", encoding="utf-8")
        except BaseException:
            os.close(fd)
            raise
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        if authorize() != path:
            raise ValueError("report reservation changed before publication")
        original, current = os.fstat(directory), path.parent.stat()
        if (path.parent.resolve() != path.parent
                or (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino)):
            raise ValueError("report directory changed before publication")
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        created = False
    finally:
        try:
            if created:
                os.unlink(temporary, dir_fd=directory)
        finally:
            os.close(directory)
