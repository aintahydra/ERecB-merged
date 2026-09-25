"""Execution-role checks shared by the provider command line tools."""

from __future__ import annotations

import os
from pathlib import Path

from erecb_triage.config import load_config


class ModeError(ValueError):
    """A command is being invoked under a profile for the other machine role."""


def require_mode(expected: str, profile: str | Path | None = None) -> None:
    """Require the selected profile to grant a command's connected/air-gap role.

    Provider CLIs accept an explicit ``--mode-profile`` or use
    ``ERECB_MODE_PROFILE``. Requiring a profile prevents a copied air-gap setup from
    silently running provider requests after its role has been configured.
    """
    if expected not in {"connected", "airgap"}:
        raise ValueError("expected mode must be connected or airgap")
    selected = profile or os.environ.get("ERECB_MODE_PROFILE")
    if selected is None:
        raise ModeError("select a machine role with --mode-profile or ERECB_MODE_PROFILE")
    try:
        config = load_config(selected)
    except (OSError, ValueError) as exc:
        raise ModeError(f"cannot load mode profile {selected}: {exc}") from exc
    actual = config.get("mode")
    if actual != expected:
        raise ModeError(f"command requires the {expected} profile; selected profile is {actual!r}")
