from __future__ import annotations

from io import StringIO
import unittest

from erecb_ipintel.progress import PercentageProgress


class PercentageProgressTests(unittest.TestCase):
    def test_reports_at_most_one_line_per_ten_percent_bucket(self) -> None:
        output = StringIO()
        reporter = PercentageProgress(output)

        for completed in range(101):
            reporter.update("work", completed, 100)

        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 11)
        self.assertEqual(lines[0], "work: 0% (0/100)")
        self.assertEqual(lines[-1], "work: 100% (100/100)")

    def test_empty_stage_is_complete(self) -> None:
        output = StringIO()
        reporter = PercentageProgress(output)

        reporter.update("work", 0, 0)
        reporter.update("work", 0, 0)

        self.assertEqual(output.getvalue(), "work: 100% (0/0)\n")


if __name__ == "__main__":
    unittest.main()
