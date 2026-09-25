"""Offline request export from a retained, dispatcher-authorized capture."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from erecb_triage.config import resolve_path
from erecb_triage.exchange import new_bundle, write_bundle
from erecb_triage.fileintel.discovery import scan_capture as scan_files
from erecb_triage.fileintel.repository import FileIntelRepository
from erecb_triage.ghintel.extractor import scan_capture as scan_repositories
from erecb_triage.ghintel.repository import GHIntelRepository
from erecb_triage.ipintel.extractor import scan_capture as scan_ips
from erecb_triage.ipintel.repository import IpIntelRepository


class RequestExportError(ValueError):
    """Export cannot safely distinguish misses from unavailable intelligence."""


def export_requests(dispatcher, capture_id: int, path: Path, *, selection: str = "missing") -> dict[str, Any]:
    """Write an indicator-only bundle; never put capture paths or content on transfer media."""
    if selection not in {"missing", "all"}:
        raise RequestExportError("selection must be missing or all")
    capture, context = dispatcher.capture_for_replay(capture_id)
    configured = dispatcher.config["processors"]
    required = ("file_retriever", "ip_retriever", "ghintel")
    if any(name not in configured for name in required):
        raise RequestExportError("request export needs FileIntel, IPIntel and GHIntel processor settings")
    policy = {name: configured[name] for name in required}
    policy_sha256 = hashlib.sha256(json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    file_result = scan_files(capture, policy["file_retriever"], dispatcher.base_dir)
    ip_result = scan_ips(capture, policy["ip_retriever"], dispatcher.base_dir)
    repo_result = scan_repositories(capture, policy["ghintel"], dispatcher.base_dir)
    # Extraction errors imply an incomplete list. Do not silently transfer partial evidence.
    issues = [*file_result.errors, *ip_result.errors, *repo_result.errors]
    if issues:
        raise RequestExportError("extraction incomplete: " + "; ".join(
            f"{issue.code}: {issue.message}" for issue in issues[:5]
        ))
    files: dict[str, str | None] = {}
    for observation in file_result.observations:
        sha256, md5 = observation["sha256_hash"], observation["md5_hash"]
        if sha256 in files and files[sha256] != md5:
            raise RequestExportError("conflicting MD5 hashes for one SHA-256")
        files[sha256] = md5
    ips = {item["ip"] for item in ip_result.observations}
    repositories = {item["identity_key"]: item["canonical_url"] for item in repo_result.observations}
    if selection == "missing":
        file_path = resolve_path(dispatcher.base_dir, policy["file_retriever"]["db_path"])
        ip_path = resolve_path(dispatcher.base_dir, policy["ip_retriever"]["db_path"])
        repo_path = resolve_path(dispatcher.base_dir, policy["ghintel"]["db_path"])
        with (FileIntelRepository(file_path) as file_db,
              IpIntelRepository(ip_path) as ip_db,
              GHIntelRepository(repo_path) as repo_db):
            for name, database in (("FileIntel", file_db), ("IPIntel", ip_db), ("GHIntel", repo_db)):
                if not database.available:
                    raise RequestExportError(f"{name} DB unavailable; use --include all to export without comparison")
            for sha256, md5 in list(files.items()):
                outcome = file_db.lookup(sha256, md5)
                if outcome.status == "hit":
                    del files[sha256]
                elif outcome.status != "miss":
                    raise RequestExportError(f"FileIntel lookup {outcome.status} for {sha256}")
            for ip in list(ips):
                outcome = ip_db.lookup(ip)
                if outcome.status == "hit":
                    ips.remove(ip)
                elif outcome.status != "miss":
                    raise RequestExportError(f"IPIntel lookup {outcome.status} for {ip}")
            for key in list(repositories):
                outcome = repo_db.lookup(key)
                if outcome.status == "hit":
                    del repositories[key]
                elif outcome.status != "miss":
                    raise RequestExportError(f"GHIntel lookup {outcome.status} for {key}")
    context.authorize_capture(capture)  # Detect capture mutation during extraction.
    source, sequence = dispatcher.staging_state.next_request_identity()
    bundle = new_bundle(
        source_instance_id=source, source_sequence=sequence, selection=selection,
        policy_sha256=policy_sha256,
        files=[{"sha256": sha256, "md5": md5} for sha256, md5 in files.items()],
        ips=sorted(ips),
        repositories=[{"identity_key": key, "canonical_url": url} for key, url in repositories.items()],
    )
    write_bundle(path, bundle)
    return {"bundle_id": bundle["bundle_id"], "source_sequence": sequence,
            "selection": selection, "counts": bundle["counts"],
            "extraction_metrics": {**file_result.metrics, **ip_result.metrics, **repo_result.metrics},
            "ip_singularities": len(ip_result.singularities), "output": str(path)}
