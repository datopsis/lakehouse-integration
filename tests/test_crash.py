"""Adversarial tests of the durability oracle and query settlement."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pyarrow as pa

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from crash import batch_rows, check_batches, settle, verify


class CrashOracle(unittest.TestCase):
    def setUp(self):
        self.attempts = [
            {"batch": 1, "outcome": "acknowledged"},
            {"batch": 2, "outcome": "in-flight"},
        ]
        self.initial = [100, None, "append"]
        self.snapshots = [self.initial, [101, 100, "append"]]

    def check(self, rows, attempts, snapshots):
        return check_batches(rows, attempts, snapshots, self.initial)

    def test_ambiguous_commit_can_be_absent_or_complete(self):
        self.assertEqual(
            self.check(batch_rows(1), self.attempts, self.snapshots),
            {"1": "fully-visible", "2": "absent"},
        )
        self.assertEqual(
            self.check(
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
                self.check(rows, self.attempts, self.snapshots)

    def test_snapshot_count_and_operation_fail_closed(self):
        for snapshots in (
            [],
            self.snapshots * 2,
            [[101, None, "overwrite"]],
            [self.initial, [101, 99, "append"]],
        ):
            with self.subTest(snapshots=snapshots), self.assertRaises(AssertionError):
                self.check(batch_rows(1), self.attempts, snapshots)

    def test_creation_snapshot_must_survive_unchanged(self):
        with self.assertRaises(AssertionError):
            self.check(batch_rows(1), self.attempts, [[99, None, "append"], [101, 99, "append"]])

    def test_broken_or_duplicate_snapshot_chain_fails(self):
        rows = batch_rows(1) + batch_rows(2)
        for snapshots in (
            self.snapshots + [[102, None, "append"]],
            self.snapshots + [[101, 101, "append"]],
        ):
            with self.assertRaises(AssertionError):
                self.check(rows, self.attempts, snapshots)

    def test_settled_outcome_cannot_change_on_later_kills(self):
        self.attempts[1]["visible"] = "absent"
        with self.assertRaises(AssertionError):
            self.check(
                batch_rows(1) + batch_rows(2),
                self.attempts,
                self.snapshots + [[102, 101, "append"]],
            )

    def test_unknown_or_duplicate_attempts_fail(self):
        for attempts in (self.attempts * 2, [{"batch": 1, "outcome": "unknown"}]):
            with self.assertRaises(AssertionError):
                self.check(batch_rows(1), attempts, self.snapshots)

    def test_reader_orders_metadata_and_rejects_independent_row_corruption(self):
        table = Mock()
        table.metadata.current_snapshot_id = 101
        table.metadata.snapshots = [
            SimpleNamespace(
                snapshot_id=101,
                parent_snapshot_id=100,
                timestamp_ms=2,
                summary=SimpleNamespace(operation=SimpleNamespace(value="append")),
            ),
            SimpleNamespace(
                snapshot_id=100,
                parent_snapshot_id=None,
                timestamp_ms=1,
                summary=SimpleNamespace(operation=SimpleNamespace(value="append")),
            ),
        ]
        p = Mock()
        p.rest_catalog.return_value.load_table.return_value = table
        spec = {"crash_test": {"attempts": self.attempts, "initial_snapshot": self.initial}}
        rows = batch_rows(1)
        for corrupt in (False, True):
            p.sql.side_effect = [rows, self.snapshots]
            table.scan.return_value.to_arrow.return_value = pa.table(
                {
                    "batch": [row[0] for row in rows],
                    "row_id": [row[1] for row in rows],
                    "label": ["corrupt" if corrupt else row[2] for row in rows],
                }
            )
            if corrupt:
                with self.assertRaises(AssertionError):
                    verify(p, spec)
            else:
                self.assertEqual(verify(p, spec)["crash_test"]["snapshots"], self.snapshots)

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
