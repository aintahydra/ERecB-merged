from __future__ import annotations

import argparse
import json
import sys
import time
from contextlib import closing
from pathlib import Path

from erecb_triage.mode import ModeError

from .config import load_config
from .db import Database
from .discovery import discover
from .enrich import enabled_providers, enrich_file, enrich_ip
from .output_writer import write_ip_tuples
from .progress import PercentageProgress
from .scanner import scan_directory


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        expected_mode = ("airgap" if args.command == "merge-db" else
                         "connected" if args.command in {"requests", "homework", "enrich", "enrich-ip", "discover", "watch"}
                         or args.command == "db" and args.action == "snapshot" else None)
        if expected_mode is not None:
            from erecb_triage.mode import require_mode
            require_mode(expected_mode, args.mode_profile)
        if args.command == "db":
            from erecb_triage.sqlite_snapshots import create_snapshot, verify_snapshot
            from .merge import _open, validate_ip_db
            if args.action == "snapshot":
                if args.output is None:
                    raise ValueError("db snapshot requires --output")
                with closing(_open(args.source.resolve(), read_only=True)) as source_db:
                    validate_ip_db(source_db)
                result = create_snapshot(args.source, args.output, producer="ipintel",
                                         version_table="schema_migrations")
            else:
                result = verify_snapshot(args.source, producer="ipintel", version_table="schema_migrations")
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command == "merge-db":
            from .merge import merge_databases
            print(json.dumps(merge_databases(args.source, args.dest, dry_run=args.dry_run,
                                             backup=args.backup), sort_keys=True))
            return 0
        config = load_config(config_path=Path(args.config).resolve() if args.config else None)
        if args.command in {"requests", "homework"}:
            return run_homework_command(args, config)
        db = Database(config.paths.db_path)
        db.initialize()
        try:
            return run_command(args, config, db)
        finally:
            db.close()
    except Exception as exc:
        print(f"error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 2 if isinstance(exc, ModeError) else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="erecb-ipintel")
    parser.add_argument("--config", help="Path to config.json, config.toml, or config.yaml")
    parser.add_argument("--mode-profile", type=Path, default=None,
                        help="machine-role profile (or set ERECB_MODE_PROFILE)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init-db")
    sub.add_parser("discover")
    sub.add_parser("watch")
    scan = sub.add_parser("scan")
    scan.add_argument("directory")
    enrich = sub.add_parser("enrich")
    enrich.add_argument("file")
    enrich.add_argument("--provider", action="append", dest="providers")
    enrich.add_argument(
        "--max-ips",
        type=int,
        help="Maximum unique IPs to query per enabled provider in this run",
    )
    enrich.add_argument(
        "--consume",
        action="store_true",
        help="Atomically remove tuples for completed IPs from the input file",
    )
    enrich_one = sub.add_parser("enrich-ip")
    enrich_one.add_argument("ip")
    enrich_one.add_argument("--provider", action="append", dest="providers")
    sub.add_parser("status")
    requests = sub.add_parser("requests", help="import verified offline request bundles")
    requests.add_argument("action", choices=("import",))
    requests.add_argument("bundle", type=Path)
    requests.add_argument("--state", type=Path)
    homework = sub.add_parser("homework", help="inspect or process unresolved IP requests")
    homework.add_argument("action", choices=("list", "run"))
    homework.add_argument("--state", type=Path)
    homework.add_argument("--limit", type=int, default=20)
    merge = sub.add_parser("merge-db", help="merge a compatible IPIntel snapshot")
    merge.add_argument("--source", type=Path, required=True)
    merge.add_argument("--dest", type=Path, required=True)
    merge.add_argument("--dry-run", action="store_true")
    merge.add_argument("--backup", action="store_true")
    snapshot = sub.add_parser("db", help="consistent SQLite snapshot and verification")
    snapshot.add_argument("action", choices=("snapshot", "verify"))
    snapshot.add_argument("--source", type=Path, required=True)
    snapshot.add_argument("--output", type=Path)
    for command_parser in sub.choices.values():
        command_parser.add_argument("--mode-profile", type=Path, default=argparse.SUPPRESS,
                                    help="machine-role profile (or set ERECB_MODE_PROFILE)")
    return parser


def run_homework_command(args: argparse.Namespace, config) -> int:
    from erecb_triage.homework import HomeworkQueue

    state = args.state or config.paths.db_path.with_name("ipintel-homework.sqlite3")
    with HomeworkQueue(state, "ip") as queue:
        if args.command == "requests":
            print(json.dumps(queue.import_bundle(args.bundle), sort_keys=True))
            return 0
        if args.action == "list":
            print(json.dumps({"pause_until": queue.pause_until(), "items": queue.list_items()},
                             indent=2, sort_keys=True))
            return 0
        providers = enabled_providers(config)
        if not providers:
            raise ValueError("no intelligence providers are enabled")
        for provider in providers:
            provider.validate_credentials()
        db = Database(config.paths.db_path)
        db.initialize()
        processed = []
        try:
            for item in queue.lease(limit=args.limit):
                try:
                    result = enrich_ip(item["identity"], config, db)
                    outcome = ("rate_limited" if result["rate_limited"] else
                               "success" if result["success"] > 0 else
                               "not_found" if result["not_found"] > 0 else "error")
                    queue.finish(item["identity"], lease_token=item["lease_token"], outcome=outcome,
                                 detail=json.dumps(result, sort_keys=True))
                    processed.append({"ip": item["identity"], "outcome": outcome})
                    if outcome == "rate_limited":
                        break
                except Exception as exc:
                    queue.finish(item["identity"], lease_token=item["lease_token"], outcome="error",
                                 detail=f"{type(exc).__name__}: {exc}")
                    processed.append({"ip": item["identity"], "outcome": "error"})
        finally:
            db.close()
        print(json.dumps(processed, sort_keys=True))
        return 0


def run_command(args: argparse.Namespace, config, db: Database) -> int:
    if args.command == "init-db":
        print(f"initialized {config.paths.db_path}")
        return 0
    if args.command == "discover":
        outputs = discover(config, db, PercentageProgress(sys.stderr).update)
        for output in outputs:
            print(output)
        print(f"processed {len(outputs)} directory unit(s)")
        return 0
    if args.command == "watch":
        while True:
            outputs = discover(config, db, PercentageProgress(sys.stderr).update)
            for output in outputs:
                print(output, flush=True)
            time.sleep(config.discovery.watch_interval_seconds)
    if args.command == "scan":
        scan_root = Path(args.directory).resolve()
        if not scan_root.is_dir():
            raise ValueError(f"scan target is not a directory: {scan_root}")
        tuples, errors = scan_directory(
            scan_root,
            config.root,
            config.extraction,
            config.discovery.follow_symlinks,
            PercentageProgress(sys.stderr).update,
        )
        output = write_ip_tuples(tuples, config.paths.output_root, scan_root.name)
        for error in errors:
            print(f"warning: {error}", file=sys.stderr)
        print(output)
        print(f"wrote {len(tuples)} tuple(s)")
        return 0
    if args.command == "enrich":
        result = enrich_file(
            Path(args.file).resolve(),
            config,
            db,
            _provider_filter(args.providers),
            PercentageProgress(sys.stderr).update,
            args.max_ips,
            args.consume,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "enrich-ip":
        result = enrich_ip(
            args.ip,
            config,
            db,
            _provider_filter(args.providers),
            PercentageProgress(sys.stderr).update,
        )
        print(json.dumps(result, sort_keys=True))
        return 0
    if args.command == "status":
        print(json.dumps(db.status_summary(), indent=2, sort_keys=True))
        return 0
    raise ValueError(f"unknown command: {args.command}")


def _provider_filter(values: list[str] | None) -> set[str] | None:
    return set(values) if values else None


if __name__ == "__main__":
    raise SystemExit(main())
