"""Adversarial tests of the durability oracle and query settlement."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from crash import batch_rows, check_batches, settle


class CrashOracle(unittest.TestCase):
    def setUp(self):
        self.attempts = [
            {"batch": 1, "outcome": "acknowledged"},
            {"batch": 2, "outcome": "in-flight"},
        ]
        self.snapshots = [[101, None, "append"]]

    def test_ambiguous_commit_can_be_absent_or_complete(self):
        self.assertEqual(
            check_batches(batch_rows(1), self.attempts, self.snapshots),
            {"1": "fully-visible", "2": "absent"},
        )
        self.assertEqual(
            check_batches(
                batch_rows(1) + batch_rows(2),
                self.attempts,
                self.snapshots + [[102, 101, "append"]],
            ),
            {"1": "fully-visible", "2": "fully-visible"},
        )

    def test_loss_partial_corruption_duplicates_unknown_rows_fail(self):
        changed = batch_rows(1)
        changed[0][2] = "corrupt"
        for rows in (
            [],
            batch_rows(2),
            batch_rows(1)[:-1],
            batch_rows(1) + batch_rows(2)[:1],
            changed,
            batch_rows(1) + batch_rows(1),
            batch_rows(1) + batch_rows(3),
        ):
            with self.subTest(rows=rows), self.assertRaises(AssertionError):
                check_batches(rows, self.attempts, self.snapshots)

    def test_snapshot_count_and_operation_fail_closed(self):
        for snapshots in (
            [],
            self.snapshots * 2,
            [[101, None, "overwrite"]],
            [[101, 99, "append"]],
        ):
            with self.subTest(snapshots=snapshots), self.assertRaises(AssertionError):
                check_batches(batch_rows(1), self.attempts, snapshots)

    def test_broken_or_duplicate_snapshot_chain_fails(self):
        rows = batch_rows(1) + batch_rows(2)
        for snapshots in (
            self.snapshots + [[102, None, "append"]],
            self.snapshots + [[101, 101, "append"]],
        ):
            with self.assertRaises(AssertionError):
                check_batches(rows, self.attempts, snapshots)

    def test_settled_outcome_cannot_change_on_later_kills(self):
        self.attempts[1]["visible"] = "absent"
        with self.assertRaises(AssertionError):
            check_batches(
                batch_rows(1) + batch_rows(2),
                self.attempts,
                self.snapshots + [[102, 101, "append"]],
            )

    def test_unknown_or_duplicate_attempts_fail(self):
        for attempts in (self.attempts * 2, [{"batch": 1, "outcome": "unknown"}]):
            with self.assertRaises(AssertionError):
                check_batches(batch_rows(1), attempts, self.snapshots)

    def test_settlement_requires_terminal_query(self):
        p = SimpleNamespace(http=Mock(side_effect=[(204, None), (200, {"state": "FAILED"})]))
        attempt = {"query_id": "q1", "terminal": False}
        settle(p, attempt)
        self.assertEqual(attempt["settled_state"], "FAILED")
        self.assertEqual(p.http.call_count, 2)
        p.http.reset_mock()
        settle(p, {"terminal": True})
        p.http.assert_not_called()
        with self.assertRaises(AssertionError):
            settle(p, {})
        p.http.side_effect = [(204, None), (404, {})]
        with self.assertRaises(AssertionError):
            settle(p, {"query_id": "missing"})


if __name__ == "__main__":
    unittest.main()
