"""Reject broad error matching in destructive maintenance negatives."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from maintenance import exact_error, key


class MaintenanceGates(unittest.TestCase):
    def test_only_exact_error_name_and_message_are_accepted(self):
        expected = {"errorName": "INVALID_ARGUMENTS", "message": "missing snapshot 123"}
        h = Mock()
        h.sql.side_effect = RuntimeError(json.dumps(expected))
        self.assertEqual(exact_error(h, "query", *expected.values()), expected)
        for error in (
            {**expected, "errorName": "PERMISSION_DENIED"},
            {**expected, "message": "missing snapshot 123 extra"},
        ):
            h.sql.side_effect = RuntimeError(json.dumps(error))
            with self.assertRaises(AssertionError):
                exact_error(h, "query", *expected.values())
        h.sql.side_effect = None
        h.sql.return_value = []
        with self.assertRaises(AssertionError):
            exact_error(h, "query", *expected.values())

    def test_inventory_rejects_other_buckets_and_schemes(self):
        self.assertEqual(key("s3://warehouse/table/data/file.parquet"), "table/data/file.parquet")
        for path in ("s3://other/table/file", "file:///warehouse/file", "https://warehouse/file"):
            with self.assertRaises(AssertionError):
                key(path)
