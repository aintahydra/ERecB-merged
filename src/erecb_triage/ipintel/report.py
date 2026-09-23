"""Escaped IP intelligence Markdown reports with atomic owned publication."""

from __future__ import annotations

import html
import ipaddress
import os
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_from_bytes
from uuid import uuid4


def escape(value) -> str:
    """Keep untrusted values inert in Markdown and HTML and on one line."""
    text = "not recorded" if value is None else str(value)
    text = "".join(
        f"\\u{ord(char):04x}" if unicodedata.category(char).startswith("C")
        or unicodedata.category(char) in {"Zl", "Zp"} else char
        for char in text
    )
    text = "".join("\\" + char if char in "\\`*_{}[]()#+-.!|~" else char for char in text)
    return html.escape(text, quote=True)


def _display(path: str | Path, base_dir: Path) -> str:
    resolved = Path(path)
    return str(resolved.relative_to(base_dir)) if resolved.is_relative_to(base_dir) else str(resolved)


def source_link(path: str | Path, base_dir: Path, report_path: Path) -> str:
    """Link with a display label relative to the repository and encoded target bytes."""
    source = Path(path)
    target = os.path.relpath(source, report_path.parent)
    return f"[{escape(_display(source, base_dir))}](<{quote_from_bytes(os.fsencode(target), safe='/.')}>)"


def render_report(capture: dict, records: list[dict], metrics: dict[str, int], errors: list, *,
                  base_dir: Path, report_path: Path, database_path: Path, database_availability: str,
                  generated_at: datetime) -> str:
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("report generation time must have a timezone")
    observations: dict[str, list[dict]] = {}
    lookups: dict[str, dict] = {}
    hits: dict[str, dict] = {}
    singularities: list[dict] = []
    for record in records:
        kind = record["type"]
        if kind == "ip_observation":
            observations.setdefault(record["ip"], []).append(record)
        elif kind == "ip_intel_lookup":
            lookups[record["ip"]] = record
        elif kind == "ip_intel_hit":
            hits[record["ip"]] = record
        elif kind == "ip_singularity":
            singularities.append(record)
    for entries in observations.values():
        entries.sort(key=lambda item: item["source_path"])

    def order(ip: str):
        return ipaddress.ip_address(ip).version, int(ipaddress.ip_address(ip)), observations[ip][0]["source_path"]

    ordered = sorted(lookups, key=lambda ip: (
        {"Yes": 0, None: 1, "No": 2}.get(hits.get(ip, {}).get("malicious"), 3), *order(ip),
    ))

    def links(ip: str) -> str:
        return "; ".join(source_link(item["source_path"], base_dir, report_path)
                         for item in observations[ip])

    def values(items: list[str]) -> str:
        return "; ".join(escape(item) for item in items) or "None"

    lines = [f"# IP Intelligence Report: {escape(capture['capture_name'])}", "", "## Summary", ""]
    summary = [
        ("Original input", _display(capture["source_path"], base_dir)),
        ("Archive filename", capture["report_stem"]),
        ("Source SHA-256", capture.get("source_sha256")),
        ("Staging started at", capture.get("staging_started_at")),
        ("Staged path", _display(capture["staged_path"], base_dir)),
        ("Database path", _display(database_path, base_dir)),
        ("Source event ID", capture["source_event_id"]),
        ("Pipeline run ID", capture["pipeline_run_id"]),
        ("Files scanned", metrics["ipintel_files_scanned"]),
        ("Files skipped", metrics["ipintel_files_skipped"]),
        ("IP-list singularities", metrics["ipintel_singularities"]),
        ("Unique IPs found", metrics["ipintel_unique_ips"]),
        ("IPs with local intelligence", metrics["ipintel_lookup_hits"]),
        ("IPs without local DB records", metrics["ipintel_lookup_misses"]),
        ("IPs with incomplete lookups", metrics["ipintel_lookup_unavailable"] + metrics["ipintel_lookup_errors"]),
        ("Lookup hits / misses / unavailable / errors", " / ".join(str(metrics[key]) for key in (
            "ipintel_lookup_hits", "ipintel_lookup_misses", "ipintel_lookup_unavailable",
            "ipintel_lookup_errors",
        ))),
        ("Database availability", database_availability),
        ("Generated at", generated_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")),
    ]
    lines.extend(f"- {label}: {escape(value)}" for label, value in summary)

    def table(title: str, headers: list[str], rows: list[list[str]]) -> None:
        lines.extend(["", f"## {title}", "", "| " + " | ".join(headers) + " |",
                      "| " + " | ".join("---" for _ in headers) + " |"])
        lines.extend("| " + " | ".join(row) + " |" for row in rows)

    table("IPs With Local Intelligence", ["IP", "Malicious", "Country", "Reverse DNS", "Sources"], [
        [ip, escape(hits[ip]["malicious"]), escape(hits[ip]["country_code"]),
         values(hits[ip]["reverse_dns"]), links(ip)]
        for ip in ordered if ip in hits
    ])
    table("IPs Without Local Intelligence", ["IP", "Sources"], [
        [ip, links(ip)] for ip in ordered if lookups[ip]["status"] == "miss"
    ])
    table("Intelligence Lookup Incomplete", ["IP", "Lookup Status", "Error Code", "Sources"], [
        [ip, escape(lookups[ip]["status"]), escape(lookups[ip]["error_code"]), links(ip)]
        for ip in ordered if lookups[ip]["status"] in {"unavailable", "error"}
    ])
    table("IP-list Singularities", ["Source path", "Reason"], [
        [source_link(item["source_path"], base_dir, report_path),
         escape(f"more than {item['threshold']} distinct valid IPs; stopped at {item['distinct_ips_at_least']}")]
        for item in sorted(singularities, key=lambda item: item["source_path"])
    ])
    lines.extend(["", "## Warnings", ""])
    lines.extend(
        f"- {escape(error.code)}: {escape(_display(error.path, base_dir))}: {escape(error.message)}"
        for error in sorted(errors, key=lambda item: (str(item.path), item.code, item.message))
    )
    if not errors:
        lines.append("None.")
    lines.extend(["", "## Details"])
    for ip in ordered:
        lookup, hit = lookups[ip], hits.get(ip)
        lines.extend(["", f"### {ip}", "", f"- Version: IPv{lookup['ip_version']}",
                      f"- Lookup status: {escape(lookup['status'])}"])
        if lookup["error_code"]:
            lines.append(f"- Error code: {escape(lookup['error_code'])}")
        lines.append("- Current source paths:")
        lines.extend(f"  - {source_link(item['source_path'], base_dir, report_path)}" for item in observations[ip])
        if hit is None:
            continue
        for label, key in (
            ("DB IP entity ID", "ip_entity_id"), ("Malicious", "malicious"),
            ("Country", "country_code"), ("WHOIS", "whois"),
            ("First seen local", "first_seen_local"), ("Last updated local", "last_updated_local"),
        ):
            lines.append(f"- {label}: {escape(hit[key])}")
        for label, key in (("Reverse DNS", "reverse_dns"), ("Related IOCs", "related_iocs"),
                           ("Related actors", "related_actors"), ("Provider results", "provider_results")):
            lines.append(f"- {label}:")
            if key == "provider_results":
                lines.extend("  - " + "; ".join(f"{escape(name)}={escape(value)}"
                                                    for name, value in item.items())
                             for item in hit[key])
            else:
                lines.extend(f"  - {escape(item)}" for item in hit[key])
            if not hit[key]:
                lines.append("  - None.")
    return "\n".join(lines) + "\n"


def publish_report(content: str, path: Path, authorize) -> None:
    """Atomically replace only a report currently owned by this staged capture."""
    if authorize() != path or not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("unsafe or unowned report path")
    temporary = f".ipintel-{uuid4().hex}.tmp"
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
