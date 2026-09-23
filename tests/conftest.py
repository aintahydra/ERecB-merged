"""Shared test-suite constants kept dependency-free for unittest and pytest users."""

from pathlib import Path


PROJECT_ROOT = Path(__file__).parents[1]
FIXTURES = PROJECT_ROOT / "tests" / "fixtures"
