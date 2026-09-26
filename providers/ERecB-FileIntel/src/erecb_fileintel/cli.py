from __future__ import annotations

import argparse
import json
import sys
from contextlib import closing
from pathlib import Path

from erecb_triage.mode import ModeError

from . import app
from .errors import ConfigError, DatabaseError, FatalScanError, ProviderAuthError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="erecb-fileintel")
    parser.add_argument("--config", default="config.yaml", help="configuration file path")
    parser.add_argument("--mode-profile", type=Path, default=None,
                        help="machine-role profile (or set ERECB_MODE_PROFILE)")
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("init-db", help="initialize the database")

    scan_parser = subparsers.add_parser("scan", help="scan a directory once")
    scan_parser.add_argument("target_dir")

    subparsers.add_parser("watch", help="watch configured input directory")
    subparsers.add_parser("show-summary", help="show database summary")
    merge_parser = subparsers.add_parser("merge-db", help="merge one File Intel database into another")
    merge_parser.add_argument("--source", required=True, help="source database to read")
    merge_parser.add_argument("--dest", required=True, help="destination database to update")
    merge_parser.add_argument("--backup", action="store_true", help="create a timestamped destination backup")
    merge_parser.add_argument("--dry-run", action="store_true", help="report changes without modifying the destination")
    merge_parser.add_argument("--intelligence-only", action="store_true", help="omit connected-machine scan paths and deduplicate snapshot imports")
    merge_parser.add_argument("--conflict-policy", choices=("warn",), default="warn", help=argparse.SUPPRESS)
    requests = subparsers.add_parser("requests", help="import verified offline request bundles")
    requests.add_argument("action", choices=("import",))
    requests.add_argument("bundle", type=Path)
    requests.add_argument("--state", type=Path)
    homework = subparsers.add_parser("homework", help="inspect or process unresolved hashes")
    homework.add_argument("action", choices=("list", "run"))
    homework.add_argument("--state", type=Path)
    homework.add_argument("--limit", type=int, default=20)
    snapshot = subparsers.add_parser("db", help="consistent SQLite snapshot and verification")
    snapshot.add_argument("action", choices=("snapshot", "verify"))
    snapshot.add_argument("--source", type=Path, required=True)
    snapshot.add_argument("--output", type=Path)
    for command_parser in subparsers.choices.values():
        command_parser.add_argument("--mode-profile", type=Path, default=argparse.SUPPRESS,
                                    help="machine-role profile (or set ERECB_MODE_PROFILE)")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        expected_mode = ("airgap" if args.command == "merge-db" else
                         "connected" if args.command in {"requests", "homework", "scan", "watch"}
                         or args.command == "db" and args.action == "snapshot" else None)
        if expected_mode is not None:
            from erecb_triage.mode import require_mode
            require_mode(expected_mode, args.mode_profile)
        if args.command == "db":
            from erecb_triage.sqlite_snapshots import create_snapshot, verify_snapshot
            from .db.connection import connect_read_only
            from .db.migrations import validate_fileintel_db
            if args.action == "snapshot":
                if args.output is None:
                    raise ValueError("db snapshot requires --output")
                with closing(connect_read_only(args.source)) as source_db:
                    validate_fileintel_db(source_db)
                result = create_snapshot(args.source, args.output, producer="fileintel",
                                         version_table="schema_version")
            else:
                result = verify_snapshot(args.source, producer="fileintel", version_table="schema_version")
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.command in {"requests", "homework"}:
            from erecb_triage.homework import HomeworkQueue
            from .config import load_config

            config = load_config(args.config)
            state = args.state or config.database_path.with_name("fileintel-homework.sqlite3")
            with HomeworkQueue(state, "file") as queue:
                if args.command == "requests":
                    print(json.dumps(queue.import_bundle(args.bundle), sort_keys=True))
                    return 0
                if args.action == "list":
                    print(json.dumps({"pause_until": queue.pause_until(), "items": queue.list_items()},
                                     indent=2, sort_keys=True))
                    return 0
                context = app.build_context(args.config)
                context.enrichment_service.validate_credentials()
                processed = []
                try:
                    for item in queue.lease(limit=args.limit):
                        payload = json.loads(item["payload"])
                        try:
                            outcome = context.enrichment_service.enrich_hash(payload["sha256"], payload["md5"])
                            queue.finish(item["identity"], lease_token=item["lease_token"], outcome=outcome)
                        except Exception as exc:
                            outcome = "error"
                            queue.finish(item["identity"], lease_token=item["lease_token"], outcome=outcome,
                                         detail=f"{type(exc).__name__}: {exc}")
                        processed.append({"sha256": item["identity"], "outcome": outcome})
                        if outcome == "rate_limited":
                            break
                finally:
                    context.repository.conn.close()
                print(json.dumps(processed, sort_keys=True))
                return 0
        if args.command == "init-db":
            app.init_db(args.config)
            print("database initialized")
            return 0
        if args.command == "scan":
            result = app.scan(args.config, args.target_dir)
            print(
                f"scan_job_id={result.scan_job_id} status={result.status} "
                f"files_seen={result.files_seen} executables_found={result.executables_found} "
                f"errors={result.error_count}"
            )
            return 1 if result.status == "partial" else 0
        if args.command == "watch":
            app.watch(args.config)
            return 0
        if args.command == "show-summary":
            counts = app.summary(args.config)
            print(
                f"files={counts['files']} malicious={counts['malicious']} "
                f"tags={counts['tags']} scans={counts['scans']}"
            )
            return 0
        if args.command == "merge-db":
            result = app.merge_db(
                args.source,
                args.dest,
                backup=args.backup,
                dry_run=args.dry_run,
                conflict_policy=args.conflict_policy,
                intelligence_only=args.intelligence_only,
            )
            print(f"source={result.source}")
            print(f"dest={result.destination}")
            if result.backup_path is not None:
                print(f"backup={result.backup_path}")
            for field_name in (
                "files_inserted", "files_merged", "tags_inserted", "file_names_inserted",
                "scan_jobs_copied", "scan_errors_copied", "observations_copied", "provider_lookups_copied",
                "watch_directories_inserted", "watch_directories_merged",
            ):
                print(f"{field_name}={getattr(result, field_name)}")
            for warning in result.warnings:
                print(f"warning={warning}", file=sys.stderr)
            print(f"warnings={len(result.warnings)}")
            print(f"status={'dry-run' if result.dry_run else 'succeeded'}")
            return 0
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except ModeError as exc:
        print(f"mode profile error: {exc}", file=sys.stderr)
        return 2
    except FatalScanError as exc:
        print(f"fatal scan error: {exc}", file=sys.stderr)
        return 3
    except DatabaseError as exc:
        print(f"database error: {exc}", file=sys.stderr)
        return 4
    except ProviderAuthError as exc:
        print(f"provider authentication error: {exc}", file=sys.stderr)
        return 5
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
