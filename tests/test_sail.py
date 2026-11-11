"""Fail-closed checks for Sail's two-lock provenance and service isolation."""

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from build import provenance_errors
from sail_build import lock_evidence


class SailGates(unittest.TestCase):
    def test_both_owner_locks_bound_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / "artifacts").mkdir()
            (source / "artifacts/sail.lock.json").write_bytes(b"sail\n")
            (source / "artifacts/rpms.lock.json").write_bytes(b"rpms\n")
            evidence = lock_evidence(source)
            digest = hashlib.sha256(b"sail\nrpms\n").hexdigest()
            self.assertEqual(evidence["lock_sha256"], digest)
            image = {
                "Architecture": "amd64",
                "Config": {
                    "Labels": {
                        "org.opencontainers.image.revision": "a" * 40,
                        "io.datopsis.artifact-lock.sha256": digest,
                    }
                },
            }
            self.assertEqual(provenance_errors(image, "a" * 40, digest), [])
            # Neither a changed RPM closure nor a Sail-only hash may pass.
            (source / "artifacts/rpms.lock.json").write_bytes(b"changed\n")
            self.assertTrue(
                provenance_errors(image, "a" * 40, lock_evidence(source)["lock_sha256"])
            )
            image["Config"]["Labels"]["io.datopsis.artifact-lock.sha256"] = hashlib.sha256(
                b"sail\n"
            ).hexdigest()
            self.assertTrue(provenance_errors(image, "a" * 40, digest))
            (source / "artifacts/rpms.lock.json").unlink()
            with self.assertRaises(FileNotFoundError):
                lock_evidence(source)

    def test_sail_only_secret_file_and_hardened_service(self):
        compose = yaml.safe_load(Path("integration/compose.sail.yaml").read_text())
        self.assertEqual(set(compose["services"]), {"sail"})
        service = compose["services"]["sail"]
        self.assertEqual(service["user"], "10001:10001")
        self.assertEqual(service["env_file"], "../.runtime/sail.env")
        self.assertEqual(service["volumes"], ["./sail/config.json:/etc/sail/config.json:ro"])
        self.assertTrue(service["read_only"])
        self.assertEqual(service["cap_drop"], ["ALL"])
        self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
        self.assertEqual(service["networks"], ["private"])
        self.assertFalse(service.get("ports"))
        self.assertEqual(len(service["tmpfs"]), 2)
        for mount in service["tmpfs"]:
            self.assertTrue(
                {"noexec", "nosuid", "nodev", "uid=10001", "gid=10001"}
                <= set(mount.split(":")[1].split(","))
            )
        self.assertFalse(
            {"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"} & service["environment"].keys()
        )


if __name__ == "__main__":
    unittest.main()
