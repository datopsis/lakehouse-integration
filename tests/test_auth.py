"""Regression gates for the additional authenticated profile and both image outputs."""

import copy
import json
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
import verify
from auth_redact import redact_reports, retain


class AuthGates(unittest.TestCase):
    def test_both_authz_outputs_must_pass_provenance(self):
        child = {
            "status": "pass",
            "revision": "a" * 40,
            "architecture": "amd64",
            "provenance_errors": [],
        }
        good = {
            "status": "pass",
            "revision": "a" * 40,
            "architecture": "amd64",
            "expected_architecture": "amd64",
            "images": {"authz": copy.deepcopy(child), "lakekeeper-authz": copy.deepcopy(child)},
        }
        with TemporaryDirectory() as directory:
            path = Path(directory)
            for image in ("authz", "lakekeeper-authz"):
                for key, value in (
                    ("status", "fail"),
                    ("revision", "b" * 40),
                    ("architecture", "arm64"),
                    ("provenance_errors", ["missing label"]),
                ):
                    broken = copy.deepcopy(good)
                    broken["images"][image][key] = value
                    (path / "builds.json").write_text(json.dumps({"datopsis-authz": broken}))
                    with (
                        patch.object(verify, "REPORTS", path),
                        patch.object(verify, "PINS", {"datopsis-authz": "a" * 40}),
                        patch.object(verify, "native_architecture", return_value="amd64"),
                    ):
                        with self.subTest(image=image, key=key), self.assertRaises(AssertionError):
                            verify.main()

    def test_final_redaction_covers_late_tracebacks_and_all_suite_secrets(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = root / "private/inventory.json"
            retain(inventory, ["first-suite-secret"])
            values = retain(inventory, ["second-suite-secret"])
            log = root / "t13-whole-stack.log"
            log.write_text("first-suite-secret")
            redact_reports(root, values)
            with log.open("a") as output:
                output.write("\nlate traceback: second-suite-secret Bearer unregistered-token")
            redact_reports(root, retain(inventory))
            self.assertNotIn("first-suite-secret", log.read_text())
            self.assertNotIn("second-suite-secret", log.read_text())
            self.assertNotIn("unregistered-token", log.read_text())
            log.write_text("-----BEGIN PRIVATE KEY-----")
            with self.assertRaises(AssertionError):
                redact_reports(root, values)
            inventory.write_text('{"invalid":"inventory"}')
            with self.assertRaises(AssertionError):
                retain(inventory)

    def test_authenticated_stages_are_mandatory_and_additional(self):
        jobs = yaml.safe_load(Path(".github/workflows/integration.yml").read_text())["jobs"]
        steps = jobs["architectures"]["steps"]
        commands = [step.get("run", "") for step in steps]
        original = next(
            i for i, command in enumerate(commands) if "python integration/probe.py" in command
        )
        for suite in ("whole-stack", "c1-c8"):
            index = next(
                i for i, command in enumerate(commands) if "auth_probe.py " + suite in command
            )
            self.assertGreater(index, original)
            self.assertNotIn("continue-on-error", steps[index])
            self.assertEqual(
                steps[index]["if"], "${{ !cancelled() && steps.build.outcome == 'success' }}"
            )
        self.assertEqual(jobs["integration"]["name"], "Integration")


if __name__ == "__main__":
    unittest.main()
