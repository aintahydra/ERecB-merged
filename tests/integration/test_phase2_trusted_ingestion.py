from __future__ import annotations

import io
import logging
import tarfile
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from erecb_triage.config import load_config
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.events import WatchEvent
from erecb_triage.processors.archive_unarchiver import ArchiveUnarchiver
from erecb_triage.processors.base import Processor, ProcessorResult
from erecb_triage.processors.input_stager import InputStager
from erecb_triage.staging import StagingState, manifest
from erecb_triage.watcher import PollingWatcher, StableCheck


class _FailingAnalysis(Processor):
    def __init__(self, name, config) -> None:
        self.name = name

    def process(self, input_records, context) -> ProcessorResult:
        raise RuntimeError("intentional analysis failure")


class _RecordingAnalysis(Processor):
    calls: list[str] = []

    def __init__(self, name, config) -> None:
        self.name = name

    def process(self, input_records, context) -> ProcessorResult:
        self.__class__.calls.append(context.event.relative_path.as_posix())
        return ProcessorResult(metrics={"recording_analysis_runs": 1})


class _FailingPreprocessor(Processor):
    def __init__(self, name, config) -> None:
        self.name = name

    def process(self, input_records, context) -> ProcessorResult:
        raise RuntimeError("intentional preprocessing failure")


def make_zip(path: Path, contents: dict[str, bytes] | None = None) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for member, data in (contents or {"evidence.txt": b"8.8.8.8\n"}).items():
            archive.writestr(member, data)


def archive_engine(**overrides) -> ArchiveUnarchiver:
    config = {
        "filename_regex": r".*\.(en_dec|enc|zip|tar\.gz)$",
        "supported_formats": [".en_dec", ".enc", ".zip", ".tar.gz"],
        "max_depth_from_event_root": 2,
        "max_archive_size_bytes": 1024 * 1024,
        "max_total_extracted_bytes_per_archive": 1024 * 1024,
        "max_extracted_files_per_archive": 100,
        "overwrite": False,
    }
    config.update(overrides)
    return ArchiveUnarchiver("test_unarchiver", config)


class ArchiveSafetyTests(unittest.TestCase):
    def test_zip_path_traversal_and_windows_separator_cannot_escape_private_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            for member in ("../outside.txt", "nested\\outside.txt"):
                archive = temporary / "sample.zip.en_dec"
                make_zip(archive, {member: b"inert"})
                output = temporary / f"payload-{len(member)}"
                output.mkdir()
                with self.assertRaisesRegex(OSError, "path_traversal"):
                    archive_engine().extract(archive, output)
                self.assertFalse((temporary / "outside.txt").exists())

    def test_tar_link_is_rejected_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            archive = temporary / "sample.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                link = tarfile.TarInfo("bad-link")
                link.type = tarfile.SYMTYPE
                link.linkname = "../outside"
                bundle.addfile(link)
            output = temporary / "payload"
            output.mkdir()
            with self.assertRaisesRegex(OSError, "special member"):
                archive_engine().extract(archive, output)

    def test_file_count_limit_fails_before_second_member_is_written(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            archive = temporary / "sample.zip"
            make_zip(archive, {"one.txt": b"one", "two.txt": b"two"})
            output = temporary / "payload"
            output.mkdir()
            with self.assertRaisesRegex(OSError, "file count"):
                archive_engine(max_extracted_files_per_archive=1).extract(archive, output)
            self.assertTrue((output / "one.txt").is_file())
            self.assertFalse((output / "two.txt").exists())

    def test_zip_staging_preflight_reports_required_and_available_space(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            archive = temporary / "sample.zip"
            make_zip(archive, {"evidence.txt": b"inert"})
            context = SimpleNamespace(
                event=SimpleNamespace(relative_path=Path("sample.zip")),
                logger=logging.getLogger("test.staging_preflight"),
            )
            with patch("erecb_triage.processors.input_stager.os.statvfs",
                       return_value=SimpleNamespace(f_bavail=1, f_frsize=1)):
                with self.assertRaisesRegex(OSError, "insufficient staging space: requires at least .* available 1 bytes"):
                    InputStager._ensure_staging_capacity(archive, temporary, archive_engine(), context)

    def test_zip_preflight_estimate_counts_files_and_uncompressed_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            archive = Path(temporary_name) / "sample.zip"
            make_zip(archive, {"one.txt": b"one", "two.txt": b"four"})
            estimate = archive_engine().estimate_extraction(archive)
            self.assertIsNotNone(estimate)
            self.assertEqual(estimate.file_count, 2)
            self.assertEqual(estimate.extracted_bytes, 7)
            self.assertEqual(estimate.method, "zip_central_directory")


class RecoveryTests(unittest.TestCase):
    def test_published_pending_capture_is_verified_and_recovered_to_ready(self) -> None:
        fixed = datetime(2026, 9, 20, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            watch, root = temporary / "in", temporary / "middle-earth"
            watch.mkdir()
            state = StagingState(temporary / "data" / "staging.sqlite3", watch, root, clock=lambda: fixed)
            try:
                row = state.reserve("sample.zip.en_dec", "a" * 64, "sample.zip", True)
                target = Path(row["staged_path"])
                target.mkdir()
                (target / "evidence.txt").write_text("inert\n", encoding="utf-8")
                state.update(row["id"], "pending", manifest(target))
                self.assertTrue(state.usable(state.get(row["id"])))
                self.assertEqual(state.get(row["id"])["status"], "ready")
            finally:
                state.close()

    def test_failed_unpublished_capture_reuses_saved_staging_identity_on_retry(self) -> None:
        fixed = datetime(2026, 9, 20, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            watch, root = temporary / "in", temporary / "middle-earth"
            watch.mkdir()
            state = StagingState(temporary / "data" / "staging.sqlite3", watch, root, clock=lambda: fixed)
            try:
                first = state.reserve("sample.zip.en_dec", "a" * 64, "sample.zip", True)
                state.update(first["id"], "failed", error="interrupted")
                retry = state.reserve("sample.zip.en_dec", "a" * 64, "sample.zip", True)
                self.assertEqual(retry["id"], first["id"])
                self.assertEqual(retry["capture_name"], first["capture_name"])
            finally:
                state.close()

    def test_recovery_refuses_a_persisted_path_outside_the_staging_root(self) -> None:
        fixed = datetime(2026, 9, 20, 12, tzinfo=timezone.utc)
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            watch, root = temporary / "in", temporary / "middle-earth"
            watch.mkdir()
            outside = temporary / "outside"
            outside.mkdir()
            state = StagingState(temporary / "data" / "staging.sqlite3", watch, root, clock=lambda: fixed)
            try:
                row = state.reserve("sample.zip.en_dec", "a" * 64, "sample.zip", True)
                state.connection.execute("UPDATE captures SET staged_path = ? WHERE id = ?", (str(outside), row["id"]))
                state.connection.commit()
                with self.assertRaisesRegex(OSError, "unsafe published staging path"):
                    state.usable(state.get(row["id"]))
            finally:
                state.close()

    def test_second_dispatcher_state_cannot_lock_the_same_staging_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            temporary = Path(temporary_name)
            watch, root = temporary / "in", temporary / "middle-earth"
            watch.mkdir()
            first = StagingState(temporary / "data-one" / "staging.sqlite3", watch, root)
            try:
                with self.assertRaises(BlockingIOError):
                    StagingState(temporary / "data-two" / "staging.sqlite3", watch, root)
            finally:
                first.close()


class WatcherAndDispatcherTests(unittest.TestCase):
    def _config(self) -> dict:
        config = load_config()
        config["pipelines"]["on_added"]["analysis"]["processors"] = [
            "ip_retriever", "file_retriever"
        ]
        return config

    def test_watcher_once_is_sorted_and_uses_injected_sleeper(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            watch = Path(temporary_name) / "in"
            watch.mkdir()
            (watch / "z.zip").write_bytes(b"z")
            (watch / "a.zip").write_bytes(b"a")
            sleeps: list[float] = []
            watcher = PollingWatcher(
                watch, StableCheck(enabled=True, interval_ms=5, unchanged_checks=1),
                sleeper=sleeps.append,
            )
            events = watcher.scan_existing()
            self.assertEqual([event.relative_path.name for event in events], ["a.zip", "z.zip"])
            self.assertEqual(sleeps, [0.005, 0.005, 0.005, 0.005])

    def test_watcher_once_announces_each_candidate_before_stability_check(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            watch = Path(temporary_name) / "in"
            watch.mkdir()
            (watch / "sample.zip").write_bytes(b"zip")
            candidates: list[str] = []
            watcher = PollingWatcher(watch, StableCheck(enabled=False))
            watcher.scan_existing(on_candidate=lambda path: candidates.append(path.name))
            self.assertEqual(candidates, ["sample.zip"])

    def test_dispatcher_logs_processor_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming = base / "in"
            incoming.mkdir()
            archive = incoming / "one.zip.en_dec"
            make_zip(archive)
            config = self._config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({
                "staging_root": "./middle-earth", "output_root": "./output",
                "staging_index_path": "./data/staging.sqlite3",
            })
            logger = logging.getLogger("test.dispatcher_lifecycle")
            with self.assertLogs(logger, level="INFO") as logs:
                with Dispatcher(config, base_dir=base, logger=logger, processor_factories={
                    "ip_retriever": _RecordingAnalysis,
                }) as dispatcher:
                    dispatcher.enqueue(WatchEvent.added(incoming, archive))
                    dispatcher.drain()
            output = "\n".join(logs.output)
            self.assertIn("processor ready phase=preprocessor processor=stage_input", output)
            self.assertIn("target queued target='one.zip.en_dec'", output)
            self.assertIn("processor start target='one.zip.en_dec' phase=preprocessor processor=stage_input", output)
            self.assertIn("processor complete target='one.zip.en_dec' phase=analysis processor=ip_retriever", output)

    def test_usable_staging_is_reused_before_capacity_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming = base / "in"
            incoming.mkdir()
            archive = incoming / "one.zip.en_dec"
            make_zip(archive)
            config = self._config()
            config["watch"]["path"] = "./in"
            config["pipelines"]["on_added"]["analysis"]["processors"] = []
            config["dispatcher"].update({
                "staging_root": "./middle-earth", "output_root": "./output",
                "staging_index_path": "./data/staging.sqlite3",
            })
            with Dispatcher(config, base_dir=base) as dispatcher:
                first = dispatcher.dispatch(WatchEvent.added(incoming, archive))
                self.assertFalse(first.errors)
                with patch("erecb_triage.processors.input_stager.os.statvfs",
                           return_value=SimpleNamespace(f_bavail=1, f_frsize=1)):
                    second = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertFalse(second.errors)

    def test_analysis_exception_does_not_suppress_later_adapter_or_later_event(self) -> None:
        _RecordingAnalysis.calls = []
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming = base / "in"
            incoming.mkdir()
            first, second = incoming / "one.zip.en_dec", incoming / "two.zip.en_dec"
            make_zip(first)
            make_zip(second)
            config = self._config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({
                "staging_root": "./middle-earth", "output_root": "./output",
                "staging_index_path": "./data/staging.sqlite3",
            })
            with Dispatcher(config, base_dir=base, processor_factories={
                "ip_retriever": _FailingAnalysis,
                "file_retriever": _RecordingAnalysis,
            }) as dispatcher:
                dispatcher.enqueue(WatchEvent.added(incoming, first))
                dispatcher.enqueue(WatchEvent.added(incoming, second))
                results = dispatcher.drain()
            self.assertEqual(len(results), 2)
            self.assertTrue(all(any(error.code == "processor_exception" for error in result.errors)
                                for result in results))
            self.assertEqual(_RecordingAnalysis.calls, ["one.zip.en_dec", "two.zip.en_dec"])

    def test_preprocessor_exception_blocks_all_analysis(self) -> None:
        _RecordingAnalysis.calls = []
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming = base / "in"
            incoming.mkdir()
            archive = incoming / "one.zip.en_dec"
            make_zip(archive)
            config = self._config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({
                "staging_root": "./middle-earth", "output_root": "./output",
                "staging_index_path": "./data/staging.sqlite3",
            })
            with Dispatcher(config, base_dir=base, processor_factories={
                "input_stager": _FailingPreprocessor,
                "file_retriever": _RecordingAnalysis,
            }) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertTrue(any(error.code == "processor_exception" for error in result.errors))
            self.assertEqual(_RecordingAnalysis.calls, [])

    def test_report_collision_for_one_adapter_does_not_suppress_the_next_adapter(self) -> None:
        _RecordingAnalysis.calls = []
        with tempfile.TemporaryDirectory() as temporary_name:
            base = Path(temporary_name)
            incoming, output = base / "in", base / "output"
            incoming.mkdir()
            output.mkdir()
            archive = incoming / "one.zip.en_dec"
            make_zip(archive)
            # No report slot owns this path; IPIntel must refuse it, FileIntel may proceed.
            (output / "one.zip.en_dec-ipintel.md").write_text("unowned\n", encoding="utf-8")
            config = self._config()
            config["watch"]["path"] = "./in"
            config["dispatcher"].update({
                "staging_root": "./middle-earth", "output_root": "./output",
                "staging_index_path": "./data/staging.sqlite3",
            })
            with Dispatcher(config, base_dir=base, processor_factories={
                "file_retriever": _RecordingAnalysis,
            }) as dispatcher:
                result = dispatcher.dispatch(WatchEvent.added(incoming, archive))
            self.assertTrue(any(error.code == "report_collision" for error in result.errors))
            self.assertEqual(_RecordingAnalysis.calls, ["one.zip.en_dec"])
