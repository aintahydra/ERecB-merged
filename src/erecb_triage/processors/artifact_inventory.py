"""Emit manifest-derived shared facts after trusted staging and before analysis."""

from __future__ import annotations

import json

from erecb_triage.inventory import InventoryError, build_inventory
from erecb_triage.processors.base import Processor, ProcessorError, ProcessorResult


class ArtifactInventory(Processor):
    def __init__(self, name: str, config: dict) -> None:
        self.name = name
        self.max_entries = config["max_entries"]

    def accepts(self, records, context) -> bool:
        return any(record.get("type") == "staged_capture" for record in records)

    def process(self, input_records, context) -> ProcessorResult:
        records, errors = [], []
        metrics = {"inventory_captures": 0, "inventory_entries": 0, "inventory_files": 0, "inventory_file_bytes": 0}
        for capture in input_records:
            if capture.get("type") != "staged_capture":
                continue
            try:
                row = context.authorize_capture(capture)
                entries = json.loads(row["manifest"])
                inventory = build_inventory(capture, entries, max_entries=self.max_entries)
            except (InventoryError, OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                errors.append(ProcessorError(context.event.path, str(exc), "artifact_inventory_error"))
                continue
            records.append(inventory)
            metrics["inventory_captures"] += 1
            metrics["inventory_entries"] += len(inventory["entries"])
            metrics["inventory_files"] += inventory["file_count"]
            metrics["inventory_file_bytes"] += inventory["total_file_bytes"]
        return ProcessorResult(records=records, errors=errors, metrics=metrics)
