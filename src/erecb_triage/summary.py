"""Capture-level status summary with no composite security verdict."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote_from_bytes
from uuid import uuid4

from erecb_triage.ipintel.report import escape
from erecb_triage.report_provenance import items as provenance_items


def render_summary(capture: dict, statuses: list[dict], records: list[dict], *, base_dir: Path,
                   generated_at: datetime) -> str:
    """Render links only for reports replaced by this capture's processor invocation."""
    def display(path: str) -> str:
        value = Path(path)
        return str(value.relative_to(base_dir)) if value.is_relative_to(base_dir) else str(value)

    lines = [f"# Triage Summary: {escape(capture['capture_name'])}", "", "## Capture", "",
             f"- Original input: {escape(display(capture['source_path']))}",
             f"- Archive filename: {escape(capture['report_stem'])}",
             f"- Source SHA-256: {escape(capture.get('source_sha256'))}",
             f"- Staged path: {escape(display(capture['staged_path']))}",
             f"- Pipeline run ID: {escape(capture['pipeline_run_id'])}",
             f"- Generated at: {escape(generated_at.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z'))}",
             "", "## Adapter Status", "", "| Adapter | State | Report | Notes |", "| --- | --- | --- | --- |"]
    insert_at = lines.index("## Adapter Status") - 1
    lines[insert_at:insert_at] = [f"- {label}: {escape(value)}" for label, value in provenance_items(capture)]
    for status in statuses:
        codes = ", ".join(status["error_codes"]) or "None"
        if status["report_current"]:
            target = os.path.relpath(status["report_path"], status["summary_path"].parent)
            report = f"[{escape(Path(status['report_path']).name)}](<{quote_from_bytes(os.fsencode(target), safe='/.')}>)"
        elif status["report_path"]:
            report = "not refreshed; an existing report may belong to an earlier capture"
        else:
            report = "not enabled"
        lines.append("| " + " | ".join((escape(status["name"]), escape(status["state"]), report, escape(codes))) + " |")
    singularities = sorted(
        (record for record in records if record.get("type") == "ip_singularity"),
        key=lambda record: record["source_path"],
    )
    lines.extend(["", "## IP-list Singularities", ""])
    if singularities:
        summary_path = Path(statuses[0]["summary_path"])
        lines.extend(["| Source path | Reason |", "| --- | --- |"])
        for record in singularities:
            target = os.path.relpath(record["source_path"], summary_path.parent)
            link = f"[{escape(display(record['source_path']))}](<{quote_from_bytes(os.fsencode(target), safe='/.')}>)"
            reason = f"more than {record['threshold']} distinct valid IPs; stopped at {record['distinct_ips_at_least']}"
            lines.append(f"| {link} | {escape(reason)} |")
    else:
        lines.append("None.")
    lines.extend(["", "## Interpretation", "",
                  "This summary is operational status, not a malware or benign verdict. A no-match, miss, unavailable database, or degraded adapter must be interpreted in its adapter report and provenance context."])
    return "\n".join(lines) + "\n"


def publish_summary(content: str, path: Path, authorize) -> None:
    if authorize() != path or not path.is_absolute() or path.parent.resolve() != path.parent:
        raise ValueError("unsafe or unowned summary path")
    temporary = f".summary-{uuid4().hex}.tmp"
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    created = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory); created = True
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content); handle.flush(); os.fsync(handle.fileno())
        if authorize() != path: raise ValueError("summary reservation changed before publication")
        os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory); os.fsync(directory); created = False
    finally:
        try:
            if created: os.unlink(temporary, dir_fd=directory)
        finally: os.close(directory)
