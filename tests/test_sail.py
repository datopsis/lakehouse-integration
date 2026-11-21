"""Fail-closed checks for Sail's two-lock provenance and service isolation."""

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from build import provenance_errors
from sail_build import lock_evidence, prepare_build
from sail_probe import static_vended_response, wire_evidence


class SailGates(unittest.TestCase):
    def test_sts_disabled_response_requires_no_vended_credentials(self):
        response = {
            "config": {
                "s3.signer": "S3V4RestSigner",
                "s3.remote-signing-enabled": "true",
                "s3.endpoint": "https://s3:8333/",
                "s3.region": "local",
            }
        }
        self.assertEqual(static_vended_response(response), response["config"])
        # Reject even the old credential-less entry, as well as real credentials.
        for entry in (None, [], [{"prefix": "s3://warehouse/table", "config": response["config"]}]):
            with self.subTest(entry=entry), self.assertRaises(AssertionError):
                static_vended_response({**response, "storage-credentials": entry})
        for key in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token"):
            leaked = copy.deepcopy(response)
            leaked["config"][key] = "unexpected"
            with self.subTest(key=key), self.assertRaises(AssertionError):
                static_vended_response(leaked)
        for key in ("s3.signer", "s3.remote-signing-enabled"):
            broken = copy.deepcopy(response)
            broken["config"][key] = "unexpected"
            with self.subTest(key=key), self.assertRaises(AssertionError):
                static_vended_response(broken)

    def test_owner_build_receives_each_native_architecture(self):
        for architecture in ("amd64", "arm64"):
            env = {"PATH": "/usr/bin"}
            command = prepare_build(Path("/source/sail-ubi"), env, Mock(), architecture)
            self.assertEqual(env["ARCHITECTURE"], architecture)
            self.assertEqual(command, ["bash", "scripts/build.sh"])
        with self.assertRaises(AssertionError):
            prepare_build(Path("/source/sail-ubi"), {"PATH": "/usr/bin"}, Mock(), "riscv64")

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
            self.assertEqual(provenance_errors(image, "a" * 40, digest, "amd64"), [])
            # Neither a changed RPM closure nor a Sail-only hash may pass.
            (source / "artifacts/rpms.lock.json").write_bytes(b"changed\n")
            self.assertTrue(
                provenance_errors(image, "a" * 40, lock_evidence(source)["lock_sha256"], "amd64")
            )
            image["Config"]["Labels"]["io.datopsis.artifact-lock.sha256"] = hashlib.sha256(
                b"sail\n"
            ).hexdigest()
            self.assertTrue(provenance_errors(image, "a" * 40, digest, "amd64"))
            (source / "artifacts/rpms.lock.json").unlink()
            with self.assertRaises(FileNotFoundError):
                lock_evidence(source)

    def test_wire_evidence_rejects_signing_or_missing_credentials(self):
        sail = "172.18.0.9"
        trace = (
            "E..POST /catalog/v1/warehouse/namespaces/integration/tables HTTP/1.1\n"
            "x-iceberg-access-delegation: vended-credentials\n"
            f"X-Forwarded-For: {sail}\n"
        )
        s3_log = '{"msg":"Found access key [REDACTED] for identity sail"}\n'
        self.assertEqual(wire_evidence(trace, sail, s3_log)["signer_posts"], 0)
        for broken_trace, broken_log in (
            ("", s3_log),
            (trace.replace(sail, "172.18.0.95"), s3_log),  # Another client's request.
            (trace.replace("vended-credentials", "client-managed"), s3_log),
            (
                trace
                + f"E..POST /catalog/v1/warehouse/s3/sign HTTP/1.1\nX-Forwarded-For: {sail}\n",
                s3_log,
            ),
            (trace, s3_log.replace("identity sail", "identity lakehouse")),
            (trace, s3_log + "Successfully validated STS session token for principal\n"),
        ):
            with (
                self.subTest(trace=broken_trace, log=broken_log),
                self.assertRaises(AssertionError),
            ):
                wire_evidence(broken_trace, sail, broken_log)

    def test_sail_only_secret_file_and_hardened_service(self):
        compose = yaml.safe_load(Path("integration/compose.sail.yaml").read_text())
        self.assertEqual(set(compose["services"]), {"sail", "sail-proxy"})
        service = compose["services"]["sail"]
        self.assertEqual(service["user"], "10001:10001")
        self.assertEqual(service["env_file"], "../.runtime/sail.env")
        self.assertEqual(
            service["volumes"],
            ["./sail/config.json:/etc/sail/config.json:ro", "../.runtime/tls/trust:/run/tls:ro"],
        )
        # Verified TLS to the catalog and S3; the owner-documented trust variable.
        environment = service["environment"]
        self.assertEqual(environment["AWS_ENDPOINT"], "https://s3:8333")
        self.assertEqual(environment["AWS_ALLOW_HTTP"], "false")
        self.assertEqual(environment["SSL_CERT_FILE"], "/run/tls/ca.crt")
        self.assertIn('uri="https://catalog:8181/catalog"', environment["SAIL_CATALOG__LIST"])
        config = json.loads(Path("integration/sail/config.json").read_text())
        self.assertEqual(
            config, {"bind": "127.0.0.1", "port": 50052, "allow_unauthenticated_remote": False}
        )
        proxy = compose["services"]["sail-proxy"]
        self.assertEqual(proxy["network_mode"], "service:sail")
        self.assertNotIn("environment", proxy)
        self.assertNotIn("env_file", proxy)
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
