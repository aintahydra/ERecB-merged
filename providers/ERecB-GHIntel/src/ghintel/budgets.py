"""Concurrency-safe conservative provider budget reservations."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal, ROUND_UP


class BudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class BudgetLimits:
    requests: int
    repositories: int
    input_tokens: int
    output_tokens: int
    cost_micro_usd: int


@dataclass(frozen=True, slots=True)
class Reservation:
    requests: int
    repositories: int
    input_tokens: int
    output_tokens: int
    cost_micro_usd: int


class BudgetLimiter:
    def __init__(self, limits: BudgetLimits, *, initial_usage: Reservation | None = None) -> None:
        self.limits = limits
        self.used = initial_usage or Reservation(0, 0, 0, 0, 0)
        if any(part < 0 for part in _parts(self.used)):
            raise ValueError("initial budget usage cannot be negative")
        self._lock = asyncio.Lock()

    async def reserve(self, value: Reservation) -> None:
        async with self._lock:
            candidate = _add(self.used, value)
            _ensure_within(candidate, self.limits)
            self.used = candidate

    async def release(self, value: Reservation) -> None:
        async with self._lock:
            candidate = _subtract(self.used, value)
            if any(part < 0 for part in _parts(candidate)):
                raise ValueError("cannot release more budget than reserved")
            self.used = candidate

    async def settle(self, reserved: Reservation, actual: Reservation) -> None:
        """Replace a conservative reservation with returned actual usage."""
        async with self._lock:
            candidate = _add(_subtract(self.used, reserved), actual)
            _ensure_within(candidate, self.limits)
            self.used = candidate


def _add(left: Reservation, right: Reservation) -> Reservation:
    return Reservation(*(a + b for a, b in zip(_parts(left), _parts(right))))


def _subtract(left: Reservation, right: Reservation) -> Reservation:
    return Reservation(*(a - b for a, b in zip(_parts(left), _parts(right))))


def _parts(value: Reservation) -> tuple[int, int, int, int, int]:
    return value.requests, value.repositories, value.input_tokens, value.output_tokens, value.cost_micro_usd


def _ensure_within(candidate: Reservation, limits: BudgetLimits) -> None:
    if any(current > limit for current, limit in zip(_parts(candidate), (limits.requests, limits.repositories, limits.input_tokens, limits.output_tokens, limits.cost_micro_usd))):
        raise BudgetExceeded("request would exceed a hard Gemini budget")
    if any(current < 0 for current in _parts(candidate)):
        raise ValueError("budget usage cannot be negative")


def maximum_cost_micro_usd(input_tokens: int, output_tokens: int, input_rate: float, output_rate: float) -> int:
    value = (Decimal(input_tokens) * Decimal(str(input_rate)) + Decimal(output_tokens) * Decimal(str(output_rate))) / Decimal(1_000_000)
    return int((value * Decimal(1_000_000)).to_integral_value(rounding=ROUND_UP))
