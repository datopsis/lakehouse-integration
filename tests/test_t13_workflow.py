"""T13 scheduling, immutable cache admission and issue state transitions."""

import copy
import hashlib
import io
import json
import sys
import tarfile
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from image_cache import recipe_hash, validate, validate_archive


class T13Workflow(unittest.TestCase):
    def test_nightly_manual_only_and_both_native_architectures(self):
        workflow = yaml.safe_load(Path(".github/workflows/t13.yml").read_text())
        # PyYAML's YAML 1.1 reader treats GitHub's `on` as a boolean key.
        triggers = workflow.get("on", workflow.get(True))
        self.assertEqual(set(triggers), {"schedule", "workflow_dispatch"})
        self.assertEqual(triggers["schedule"], [{"cron": "41 2 * * *"}])
        main = yaml.safe_load(Path(".github/workflows/integration.yml").read_text())
        reusable = yaml.safe_load(Path(".github/workflows/t13-native.yml").read_text())
        self.assertEqual(workflow["jobs"]["t13"]["uses"], "$/.github/workflows/t13-native.yml")
        self.assertEqual(set(reusable.get("on", reusable.get(True))), {"workflow_call"})
        job = reusable["jobs"]["native"]
        self.assertEqual(
            job["if"],
            "${{ github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' }}",
        )
        bridge = yaml.safe_load(Path(".github/workflows/idp-bakeoff.yml").read_text())
        self.assertEqual(set(bridge.get("on", bridge.get(True))), {"workflow_dispatch"})
        self.assertEqual(bridge["jobs"]["t13"]["uses"], "$/.github/workflows/t13-native.yml")
        self.assertEqual(bridge["jobs"]["t13"]["if"], "${{ inputs.suite == 't13' }}")
        self.assertEqual(job["strategy"], main["jobs"]["architectures"]["strategy"])
        commands = [step.get("run", "") for step in job["steps"]]
        self.assertTrue(any("auth_probe.py whole-stack" in c for c in commands))
        self.assertFalse(any("auth_probe.py c1-c8" in c for c in commands))
        self.assertTrue(all("continue-on-error" not in step for step in job["steps"]))
        tracker = workflow["jobs"]["tracking"]
        self.assertEqual(tracker["permissions"], {"issues": "write"})
        self.assertEqual(tracker["if"], "${{ always() && github.event_name == 'schedule' }}")
        self.assertTrue(
            all("actions/checkout" not in step.get("uses", "") for step in tracker["steps"])
        )
        self.assertTrue(
            all(
                "permissions" not in j for name, j in workflow["jobs"].items() if name != "tracking"
            )
        )

    def tracker(self):
        workflow = yaml.safe_load(Path(".github/workflows/t13.yml").read_text())
        script = (
            workflow["jobs"]["tracking"]["steps"][0]["run"]
            .split("<<'PY'\n", 1)[1]
            .rsplit("\nPY", 1)[0]
        )
        namespace = {"__name__": "test_issue_tracker"}
        exec(compile(script, "t13 scheduled tracker", "exec"), namespace)
        return namespace

    def test_one_tracking_issue_and_comments_only_on_result_changes(self):
        tracker = self.tracker()
        plan = tracker["operations"]
        url = "https://github.com/datopsis/lakehouse-integration/actions/runs/123"
        self.assertEqual(plan([], "success", url), [])
        actions = plan([], "failure", url)
        self.assertEqual([a[0] for a in actions], ["create"])
        self.assertIn("Built with [Cloudroom]", actions[0][2])
        issue = {
            "number": 8,
            "title": tracker["TITLE"],
            "state": "OPEN",
            "body": actions[0][2],
            "comments": [],
        }
        self.assertEqual([a[0] for a in plan([issue], "failure", url)], ["edit"])
        recovery = plan([issue], "success", url)
        self.assertEqual([a[0] for a in recovery], ["comment", "edit", "close"])
        # Retry after the comment succeeded but body edit failed.
        issue["comments"] = [{"body": recovery[0][2]}]
        self.assertEqual([a[0] for a in plan([issue], "success", url)], ["edit", "close"])
        issue.update(state="CLOSED", body=recovery[1][2])
        self.assertEqual([a[0] for a in plan([issue], "success", url)], ["edit"])
        self.assertEqual(
            [a[0] for a in plan([issue], "failure", url)], ["reopen", "comment", "edit"]
        )
        # Even if duplicate titles already exist, never create another issue.
        duplicate = dict(issue, number=10)
        self.assertTrue(all(a[1] == "8" for a in plan([duplicate, issue], "failure", url)))
        self.assertEqual(plan([dict(issue, title="unrelated")], "success", url), [])

    def test_cache_manifest_cannot_change_pin_architecture_lock_or_recipe(self):
        manifest = {
            "schema": 1,
            "repo": "rauthy-ubi",
            "revision": "a" * 40,
            "architecture": "amd64",
            "lock_sha256": "b" * 64,
            "recipe_sha256": recipe_hash(),
            "archive_sha256": "c" * 64,
            "images": {"localhost/rauthy-ubi:integration": "sha256:" + "d" * 64},
        }
        validate(manifest, "rauthy-ubi", "a" * 40, "amd64", "b" * 64)
        for field in (
            "repo",
            "revision",
            "architecture",
            "lock_sha256",
            "recipe_sha256",
            "archive_sha256",
        ):
            changed = copy.deepcopy(manifest)
            changed[field] = "wrong"
            with self.subTest(field=field), self.assertRaises(AssertionError):
                validate(changed, "rauthy-ubi", "a" * 40, "amd64", "b" * 64)

    def test_cached_archive_cannot_replace_other_images_or_configs(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "images.tar.gz"
            config = b'{"architecture":"amd64"}'
            expected = {
                "localhost/rauthy-ubi:integration": "sha256:" + hashlib.sha256(config).hexdigest()
            }

            def archive(tags):
                with tarfile.open(path, "w:gz") as bundle:
                    for name, data in [
                        ("config.json", config),
                        (
                            "manifest.json",
                            json.dumps([{"Config": "config.json", "RepoTags": tags}]).encode(),
                        ),
                    ]:
                        member = tarfile.TarInfo(name)
                        member.size = len(data)
                        bundle.addfile(member, io.BytesIO(data))

            archive(list(expected))
            validate_archive(path, expected)
            archive([*expected, "localhost/postgresql-lakekeeper-ubi:integration"])
            with self.assertRaises(AssertionError):
                validate_archive(path, expected)
            archive(list(expected))
            with self.assertRaises(AssertionError):
                validate_archive(path, dict.fromkeys(expected, "sha256:" + "0" * 64))


if __name__ == "__main__":
    unittest.main()
