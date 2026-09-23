import asyncio

import pytest

from ghintel.budgets import BudgetExceeded, BudgetLimiter, BudgetLimits, Reservation, maximum_cost_micro_usd


def test_reservation_cannot_cross_hard_limit() -> None:
    async def run() -> None:
        limiter = BudgetLimiter(BudgetLimits(1, 1, 10, 10, 1_000))
        await limiter.reserve(Reservation(1, 1, 5, 5, 500))
        with pytest.raises(BudgetExceeded):
            await limiter.reserve(Reservation(1, 0, 0, 0, 0))

    asyncio.run(run())


def test_cost_is_conservatively_rounded() -> None:
    assert maximum_cost_micro_usd(1, 1, 0.1, 0.1) == 1
