"""Canaries must never accept wrong rows, wrong schemas, or unrelated failures."""

import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from evolution import SAIL_ERRORS, normalized, sail_outcome, spark_schema


class EvolutionGates(unittest.TestCase):
    def test_canary_requires_exact_exception_and_announces_exact_success(self):
        fields = [[1, "id", "int"]]
        error = {"type": "KnownError", "message": "exact measured failure"}
        with patch.dict(SAIL_ERRORS, {"test": error}, clear=True):
            self.assertEqual(
                sail_outcome({"error": error}, fields, [[1]], "test")["status"], "expected-failure"
            )
            for wrong in (
                {**error, "type": "OtherError"},
                {**error, "message": error["message"] + " extra"},
            ):
                self.assertEqual(
                    sail_outcome({"error": wrong}, fields, [[1]], "test")["status"],
                    "unexpected-error",
                )
            result = {"schema": spark_schema(fields), "rows": [[1]]}
            output = io.StringIO()
            with patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(output):
                self.assertEqual(
                    sail_outcome(result, fields, [[1]], "test")["status"], "upstream-fixed"
                )
            self.assertIn("::notice", output.getvalue())
            for wrong in (
                {**result, "rows": []},
                {**result, "schema": spark_schema([[1, "renamed", "int"]])},
            ):
                with self.assertRaises(AssertionError):
                    sail_outcome(wrong, fields, [[1]], "test")

    def test_nested_rows_keep_nulls_values_and_column_order(self):
        self.assertEqual(
            normalized([{"id": 1, "details": {"code": 10, "extra": None}}]), [[1, [10, None]]]
        )
