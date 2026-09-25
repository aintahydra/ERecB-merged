from __future__ import annotations

import argparse
import json
import logging
import sqlite3
from pathlib import Path

from erecb_triage.config import load_config, resolve_path
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.db_import import ImportErrorSet, import_database_set
from erecb_triage.logging_setup import configure_operational_logging
from erecb_triage.readiness import readiness
from erecb_triage.request_export import RequestExportError, export_requests
from erecb_triage.watcher import PollingWatcher, StableCheck


def main() -> int:
    parser = argparse.ArgumentParser(description="ERecB offline triage watcher")
    parser.add_argument("--config", default=None,
                        help="optional YAML profile; omit for the built-in staging/unarchiving defaults")
    parser.add_argument("--once", action="store_true", help="scan existing direct children and exit")
    parser.add_argument("--check", action="store_true", help="run read-only readiness diagnostics and exit")
    commands = parser.add_subparsers(dest="command")
    report = commands.add_parser("report", help="regenerate reports for a retained staged capture")
    report.add_argument("--capture", type=int, required=True, help="capture ID from 'captures list'")
    report.add_argument("--config", default=argparse.SUPPRESS, help="analysis YAML profile")
    captures = commands.add_parser("captures", help="inspect retained staged captures")
    captures.add_argument("action", choices=("list",))
    captures.add_argument("--config", default=argparse.SUPPRESS, help="YAML profile")
    requests = commands.add_parser("requests", help="offline indicator request exchange")
    requests.add_argument("action", choices=("export",))
    requests.add_argument("--capture", type=int, required=True)
    requests.add_argument("--output", type=Path, required=True)
    requests.add_argument("--include", choices=("missing", "all"), default="missing")
    requests.add_argument("--config", default=argparse.SUPPRESS, help="analysis YAML profile")
    databases = commands.add_parser("db", help="air-gap intelligence database maintenance")
    databases.add_argument("action", choices=("import",))
    databases.add_argument("--fileintel", type=Path, required=True, help="verified FileIntel snapshot")
    databases.add_argument("--ipintel", type=Path, required=True, help="verified IPIntel snapshot")
    databases.add_argument("--ghintel", type=Path, required=True, help="verified GHIntel snapshot")
    databases.add_argument("--dry-run", action="store_true")
    databases.add_argument("--config", default=argparse.SUPPRESS, help="analysis YAML profile")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logger = logging.getLogger("erecb_triage")
    base_dir = Path.cwd().resolve()
    selected_config = args.config or ("config/airgap.yaml" if args.command in {"report", "requests", "db"} else None)
    config = load_config(selected_config)
    if config.get("mode") == "connected" and not args.check:
        parser.error("this triage command requires an airgap profile; connected mode uses the provider CLIs")
    if args.check:
        result = readiness(config, base_dir)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 2
    # A maintenance preview must not create or rotate an operational log.
    log_path = None if args.command == "db" and args.dry_run else configure_operational_logging(config, base_dir)
    logger = logging.getLogger("erecb_triage")
    if args.command == "db":
        try:
            result = import_database_set(config, base_dir, fileintel=args.fileintel,
                                         ipintel=args.ipintel, ghintel=args.ghintel,
                                         dry_run=args.dry_run)
        except (ImportErrorSet, OSError, ValueError, ImportError, sqlite3.Error) as exc:
            logger.error("database import failed: %s", exc)
            return 2
        print(json.dumps(result, indent=2, sort_keys=True, default=str))
        return 0
    if args.command is not None:
        if args.once:
            parser.error("--once cannot be combined with a subcommand")
        with Dispatcher(config, base_dir=base_dir) as dispatcher:
            if args.command == "captures":
                print(json.dumps(dispatcher.list_captures(), indent=2, sort_keys=True))
                return 0
            if args.command == "report":
                result = dispatcher.replay(args.capture)
                print(json.dumps({"capture_id": args.capture, "statuses": result.statuses,
                                  "errors": [{"code": error.code, "message": error.message}
                                             for error in result.errors]}, indent=2, sort_keys=True, default=str))
                return int(bool(result.errors))
            if args.command == "requests":
                try:
                    result = export_requests(dispatcher, args.capture, args.output, selection=args.include)
                except (RequestExportError, OSError, ValueError) as exc:
                    logger.error("request export failed: %s", exc)
                    return 2
                print(json.dumps(result, indent=2, sort_keys=True))
                return 0
    logger.info("run start mode=%s config=%s base_dir=%s log_path=%s",
                "once" if args.once else "watch", selected_config or "built-in", base_dir, log_path or "terminal-only")
    watch_config = config["watch"]
    stable_config = watch_config.get("stable_check", {})
    with Dispatcher(config, base_dir=base_dir) as dispatcher:
        watcher = PollingWatcher(
            resolve_path(base_dir, watch_config.get("path", "./in")),
            StableCheck(
                enabled=bool(stable_config.get("enabled", True)),
                interval_ms=int(stable_config.get("interval_ms", 250)),
                unchanged_checks=int(stable_config.get("unchanged_checks", 3)),
            ),
            poll_interval_ms=int(watch_config.get("event_debounce_ms", 500)),
        )
        if args.once:
            logger.info("scanning existing targets path=%s", watcher.watch_path)

            def announce_candidate(path: Path) -> None:
                logger.info("target candidate target=%r checking_stability=true", path.name)

            events = watcher.scan_existing(on_candidate=announce_candidate)
            logger.info("targets ready count=%d", len(events))
            for event in events:
                dispatcher.enqueue(event)
            results = dispatcher.drain()
            failed = sum(bool(result.errors) for result in results)
            logger.info("one-shot complete targets=%d failed_targets=%d", len(results), failed)
            return int(bool(failed))

        def drain_and_retry():
            for result in dispatcher.drain():
                for error in result.errors:
                    if error.code == "source_unstable":
                        watcher.retry(error.path)

        def announce_candidate(path: Path) -> None:
            logger.info("target candidate target=%r checking_stability=true", path.name)

        watcher.watch_forever(dispatcher.enqueue, drain_and_retry, announce_candidate)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
