from __future__ import annotations

import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from erecb_triage.processors.archive_unarchiver import ArchiveUnarchiver
from erecb_triage.processors.base import Processor, ProcessorError, ProcessorResult
from erecb_triage.staging import fsync_directory, fingerprint, hash_file, manifest, regular_reader


class InputStager(Processor):
    """Publish verified snapshots and emit only indexed, completed captures."""

    def __init__(self, name: str, config: dict[str, Any]) -> None:
        self.name, self.config = name, config

    def process(self, input_records: list[dict[str, Any]], context: Any) -> ProcessorResult:
        source = context.event.path
        state = context.staging_state
        row = None
        nested_rows = []
        published = False
        try:
            if any(record.get("type") == "staged_capture" for record in input_records):
                return ProcessorResult()
            if source.is_symlink():
                raise OSError("symlink capture inputs are not accepted")
            engine_name = self.config["unarchiver"]
            engine = ArchiveUnarchiver(engine_name, context.config["processors"][engine_name])
            archive = source.is_file() and engine._is_candidate(source)
            directory = source.is_dir()
            if not archive and not self.config.get(
                "copy_directories" if directory else "copy_files", True
            ):
                return ProcessorResult(metrics={"inputs_skipped": 1})
            if not directory and not source.is_file():
                raise OSError("capture input must be a regular file or directory")

            if archive:
                engine.validate(source)
            digest = hash_file(source) if archive else ""
            label = self._label(source.name) if archive else source.name
            row = state.reserve(
                context.event.relative_path.as_posix(), digest, label, archive,
            )
            state.cleanup_partial(row["id"])
            if state.usable(row):
                context.logger.info("staging reuse target=%r capture=%r",
                                    context.event.relative_path.as_posix(), row["capture_name"])
                return self._result(state.get(row["id"]), context, "skipped_existing_output")
            if archive:
                self._ensure_staging_capacity(source, state.partial, engine, context)

            state.update(row["id"], "pending")
            target = Path(row["staged_path"])
            with TemporaryDirectory(prefix=f"capture-{row['id']}-", dir=state.partial) as work:
                payload = Path(work) / "payload"
                payload.mkdir(mode=0o700)
                metrics = {}
                if archive:
                    private_source = Path(work) / "source" / source.name
                    context.logger.info("archive private_copy start target=%r source_bytes=%d",
                                        context.event.relative_path.as_posix(), source.stat().st_size)
                    self._copy_file(source, private_source, digest)
                    context.logger.info("archive private_copy complete target=%r",
                                        context.event.relative_path.as_posix())
                    context.logger.info("archive extraction start target=%r", context.event.relative_path.as_posix())
                    _, count, size = engine.extract(private_source, payload)
                    metrics = {"archives_extracted": 1, "files_extracted": count,
                               "bytes_extracted": size}
                    context.logger.info("archive extraction complete target=%r extracted_files=%d extracted_bytes=%d",
                                        context.event.relative_path.as_posix(), count, size)
                    if hash_file(source) != digest:
                        raise OSError("source_unstable: archive changed during extraction")
                    method = "archive_extracted"
                elif directory:
                    original = manifest(source)
                    for entry in original:
                        dest = payload / entry["path"]
                        if entry["type"] == "directory":
                            dest.mkdir(parents=True, exist_ok=True, mode=0o700)
                        else:
                            self._copy_file(source / entry["path"], dest, entry["sha256"])
                    if manifest(payload) != original or manifest(source) != original:
                        raise OSError("source_unstable: directory changed during copying")
                    if self.config.get("extract_nested_archives", True):
                        for nested, _ in list(engine._discover(payload)):
                            relative = nested.relative_to(payload)
                            engine.validate(nested)
                            child = state.reserve(
                                (context.event.relative_path / relative).as_posix(),
                                hash_file(nested), self._label(nested.name), True,
                                parent=target / relative.parent, existing_parent=nested.parent,
                            )
                            nested_rows.append(child)
                            output = nested.parent / child["capture_name"]
                            output.mkdir(mode=0o700)
                            _, count, size = engine.extract(nested, output)
                            state.update(child["id"], "pending", manifest(output))
                            for key, value in (("archives_extracted", 1),
                                               ("files_extracted", count),
                                               ("bytes_extracted", size)):
                                metrics[key] = metrics.get(key, 0) + value
                    if manifest(source) != original:
                        raise OSError("source_unstable: directory changed during staging")
                    method = "directory_copied"
                else:
                    self._copy_file(source, payload / source.name)
                    method = "file_copied"

                entries = manifest(payload)
                state.update(row["id"], "pending", entries)
                if os.path.lexists(target):
                    raise OSError("output_collision: staging destination became occupied")
                payload.rename(target)
                fsync_directory(target.parent)
                published = True
                for child in nested_rows:
                    state.update(child["id"], "ready")
                state.update(row["id"], "ready")
                return self._result(state.get(row["id"]), context, method, metrics)
        except Exception as exc:
            # Published-but-pending output keeps its manifest for verified crash recovery.
            if row is not None and not published and not os.path.lexists(row["staged_path"]):
                for child in nested_rows:
                    state.update(child["id"], "failed", error=str(exc))
                state.update(row["id"], "failed", error=str(exc))
            message = str(exc)
            code = message.split(":", 1)[0]
            if code not in {"source_unstable", "format_mismatch", "path_traversal", "naming_error",
                            "output_collision", "report_collision", "recovery_error"}:
                code = "staging_error"
            return ProcessorResult(errors=[ProcessorError(source, message, code)],
                                   metrics={"staging_errors": 1})

    def _label(self, name: str) -> str:
        naming = self.config.get("archive_output_naming", {})
        for suffix in naming.get("strip_final_suffixes", [".en_dec", ".enc"]):
            if name.lower().endswith(suffix):
                return name[:-len(suffix)]
        return name

    @staticmethod
    def _copy_file(source: Path, target: Path, expected: str | None = None) -> None:
        before = fingerprint(source)
        digest = hashlib.sha256()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with regular_reader(source) as reader, target.open("xb") as writer:
            os.chmod(target, 0o600)
            while chunk := reader.read(1024 * 1024):
                digest.update(chunk)
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
        if before != fingerprint(source) or (expected is not None and digest.hexdigest() != expected):
            raise OSError("source_unstable: file changed during copying")

    @staticmethod
    def _ensure_staging_capacity(source: Path, partial_root: Path, engine: ArchiveUnarchiver, context: Any) -> None:
        """Estimate an archive and reject it before copying when its work area cannot fit it.

        The stager needs a private source copy and extracted payload concurrently. The estimate
        is ZIP central-directory metadata or a TAR header scan; both remain subject to the
        existing runtime limits during extraction.
        """
        context.logger.info("archive preflight start target=%r format=%s",
                            context.event.relative_path.as_posix(), engine._archive_format(source))
        estimate = engine.estimate_extraction(source)
        if estimate is None:
            context.logger.warning("archive preflight target=%r outcome=unavailable reason=unsupported_estimate_format",
                                   context.event.relative_path.as_posix())
            return
        try:
            engine.validate_estimate(estimate)
        except OSError as exc:
            context.logger.warning(
                "archive preflight target=%r format=%s estimated_files=%d estimated_extracted_bytes=%d outcome=rejected reason=%s",
                context.event.relative_path.as_posix(), estimate.archive_format, estimate.file_count,
                estimate.extracted_bytes, exc,
            )
            raise
        source_bytes = source.stat().st_size
        overhead = max(64 * 1024 * 1024, estimate.extracted_bytes // 20)
        required = source_bytes + estimate.extracted_bytes + overhead
        info = os.statvfs(partial_root)
        available = info.f_bavail * info.f_frsize
        fields = (context.event.relative_path.as_posix(), estimate.archive_format, estimate.method,
                  source_bytes, estimate.file_count, estimate.extracted_bytes, overhead, required, available)
        if available < required:
            context.logger.warning(
                "archive preflight target=%r format=%s method=%s archive_bytes=%d estimated_files=%d "
                "estimated_extracted_bytes=%d overhead_bytes=%d required_bytes=%d available_bytes=%d outcome=rejected",
                *fields,
            )
            raise OSError(
                "insufficient staging space: "
                f"requires at least {required} bytes for private archive copy and extraction; "
                f"available {available} bytes"
            )
        context.logger.info(
            "archive preflight target=%r format=%s method=%s archive_bytes=%d estimated_files=%d "
            "estimated_extracted_bytes=%d overhead_bytes=%d required_bytes=%d available_bytes=%d outcome=accepted",
            *fields,
        )

    @staticmethod
    def _result(row, context, method: str, metrics=None) -> ProcessorResult:
        record = {
            "type": "staged_capture", "capture_name": row["capture_name"],
            "source_name": context.event.source_name, "source_path": str(context.event.path),
            "source_relative_path": row["source_relative_path"],
            "report_stem": row["report_stem"], "staged_path": row["staged_path"],
            "staging_method": method,
            "source_event_id": context.event.id, "pipeline_run_id": context.run_id,
        }
        if row["source_sha256"]:
            record.update(source_sha256=row["source_sha256"],
                          staging_started_at=row["staging_started_at"])
        records = [record]
        if method == "skipped_existing_output":
            records.append({"type": "skipped_existing_output", "output_path": row["staged_path"]})
        return ProcessorResult(records=records, metrics={"captures_staged": 1, **(metrics or {})})
