from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from erecb_triage.config import load_config, resolve_path
from erecb_triage.dispatcher import Dispatcher
from erecb_triage.logging_setup import configure_operational_logging
from erecb_triage.readiness import readiness
from erecb_triage.watcher import PollingWatcher, StableCheck


def main() -> int:
    parser = argparse.ArgumentParser(description="ERecB offline triage watcher")
    parser.add_argument("--config", default=None,
                        help="optional YAML profile; omit for the built-in staging/unarchiving defaults")
    parser.add_argument("--once", action="store_true", help="scan existing direct children and exit")
    parser.add_argument("--check", action="store_true", help="run read-only readiness diagnostics and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logger = logging.getLogger("erecb_triage")
    base_dir = Path.cwd().resolve()
    config = load_config(args.config)
    if args.check:
        result = readiness(config, base_dir)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 2
    log_path = configure_operational_logging(config, base_dir)
    logger = logging.getLogger("erecb_triage")
    logger.info("run start mode=%s config=%s base_dir=%s log_path=%s",
                "once" if args.once else "watch", args.config or "built-in", base_dir, log_path or "terminal-only")
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
