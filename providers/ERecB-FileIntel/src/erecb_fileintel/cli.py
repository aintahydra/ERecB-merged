from __future__ import annotations

import argparse
import sys

from . import app
from .errors import ConfigError, DatabaseError, FatalScanError, ProviderAuthError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="erecb-fileintel")
    parser.add_argument("--config", default="config.yaml", help="configuration file path")
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
    merge_parser.add_argument("--conflict-policy", choices=("warn",), default="warn", help=argparse.SUPPRESS)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
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
