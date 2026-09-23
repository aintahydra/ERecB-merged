from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .config import load_config
from .db import Database
from .discovery import discover
from .enrich import enrich_file, enrich_ip
from .output_writer import write_ip_tuples
from .progress import PercentageProgress
from .scanner import scan_directory


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = load_config(config_path=Path(args.config).resolve() if args.config else None)
        db = Database(config.paths.db_path)
        db.initialize()
        try:
            return run_command(args, config, db)
        finally:
            db.close()
    except Exception as exc:
        print(f"error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="erecb-ipintel")
    parser.add_argument("--config", help="Path to config.json, config.toml, or config.yaml")
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
    return parser


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
