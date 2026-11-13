"""Evidence regressions: authorization denial must not hide other failures."""

import unittest
from pathlib import Path

import run  # noqa: F401
import yaml
from exercise import denial
from pyiceberg.exceptions import ForbiddenError, NoSuchTableError, UnauthorizedError


class EvaluationSafety(unittest.TestCase):
    def test_only_authorization_or_hidden_object_denials_are_accepted(self):
        def raises(error):
            def operation():
                raise error

            return operation

        for error in (ForbiddenError("denied"), NoSuchTableError("hidden")):
            self.assertEqual(denial(raises(error))["type"], type(error).__name__)
        for error in (
            UnauthorizedError("bad token"),
            TimeoutError("network"),
            ValueError("bad schema"),
        ):
            with self.assertRaises(type(error)):
                denial(raises(error))
        with self.assertRaisesRegex(AssertionError, "succeeded"):
            denial(lambda: None)

    def test_new_workflow_is_manual_only_and_not_a_required_dependency(self):
        root = Path(__file__).resolve().parents[2]
        workflow = yaml.safe_load((root / ".github/workflows/authz-evaluation.yml").read_text())
        self.assertEqual(workflow[True], {"workflow_dispatch": None})
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        matrix = workflow["jobs"]["evaluate"]["strategy"]["matrix"]["include"]
        self.assertEqual({r["runner"] for r in matrix}, {"ubuntu-24.04", "ubuntu-24.04-arm"})
        main = (root / ".github/workflows/integration.yml").read_text()
        self.assertNotIn("authz", main)


if __name__ == "__main__":
    unittest.main()
