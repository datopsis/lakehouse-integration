"""Regression tests for gates that must never accidentally turn a failure green."""

import copy
import os
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from build import artifact_lock, native_architecture, provenance_errors, sha
from gates import DECODER_ERROR, EXPECTED_ROWS, encoding_read, redact, remote_signing_failure
from probe import check_container_config
from remote_signing import sanitize


class Gates(unittest.TestCase):
    def test_native_architecture_rejects_cross_builds_and_unsupported_hosts(self):
        with patch("build.platform.system", return_value="Linux"):
            for machine, arch in (("x86_64", "amd64"), ("aarch64", "arm64")):
                with patch("build.platform.machine", return_value=machine):
                    with patch.dict(os.environ, {"INTEGRATION_ARCH": arch}):
                        self.assertEqual(native_architecture(), arch)
                    with patch.dict(os.environ, {"INTEGRATION_ARCH": "wrong"}):
                        with self.assertRaises(AssertionError):
                            native_architecture()
            with patch("build.platform.machine", return_value="riscv64"):
                with self.assertRaises(AssertionError):
                    native_architecture()
        with patch("build.platform.system", return_value="Darwin"):
            with self.assertRaises(AssertionError):
                native_architecture()

    def test_exact_provenance_on_both_architectures(self):
        for arch, foreign in (("amd64", "arm64"), ("arm64", "amd64")):
            image = {
                "Architecture": arch,
                "Config": {
                    "Labels": {
                        "org.opencontainers.image.revision": "a" * 40,
                        "io.datopsis.artifact-lock.sha256": "b" * 64,
                    }
                },
            }
            with self.subTest(arch=arch):
                self.assertEqual(provenance_errors(image, "a" * 40, "b" * 64, arch), [])
                for field in image["Config"]["Labels"]:
                    for value in (None, "", "wrong"):
                        with self.subTest(field=field, value=value):
                            broken = copy.deepcopy(image)
                            broken["Config"]["Labels"][field] = value
                            self.assertTrue(provenance_errors(broken, "a" * 40, "b" * 64, arch))
                self.assertTrue(provenance_errors(image, "a" * 40, "b" * 64, foreign))
                image["Config"]["Labels"] = None
                self.assertTrue(provenance_errors(image, "a" * 40, "b" * 64, arch))

    def test_lock_selection_cannot_substitute_other_architecture(self):
        with TemporaryDirectory() as directory:
            source = Path(directory)
            for arch in ("amd64", "arm64"):
                lock = artifact_lock(source, "postgresql-lakekeeper-ubi", arch)
                self.assertEqual(lock, source / f"artifacts/locks/{arch}.json")
                lock.parent.mkdir(parents=True, exist_ok=True)
                lock.write_text(arch)
            amd64 = sha(artifact_lock(source, "postgresql-lakekeeper-ubi", "amd64"))
            arm64 = sha(artifact_lock(source, "postgresql-lakekeeper-ubi", "arm64"))
            self.assertNotEqual(amd64, arm64)
            image = {
                "Architecture": "arm64",
                "Config": {
                    "Labels": {
                        "org.opencontainers.image.revision": "a" * 40,
                        "io.datopsis.artifact-lock.sha256": amd64,
                    }
                },
            }
            self.assertTrue(provenance_errors(image, "a" * 40, arm64, "arm64"))
            for repo in ("lakekeeper", "seaweedfs", "trino"):
                for arch in ("amd64", "arm64"):
                    self.assertEqual(
                        artifact_lock(source, repo + "-ubi", arch),
                        source / f"artifacts/{repo}.lock.json",
                    )

    def test_workflow_requires_both_native_jobs_without_fail_fast(self):
        jobs = yaml.safe_load(Path(".github/workflows/integration.yml").read_text())["jobs"]
        architectures = jobs["architectures"]
        self.assertFalse(architectures["strategy"]["fail-fast"])
        self.assertEqual(
            architectures["strategy"]["matrix"]["include"],
            [
                {"arch": "amd64", "machine": "x86_64", "runner": "ubuntu-24.04"},
                {"arch": "arm64", "machine": "aarch64", "runner": "ubuntu-24.04-arm"},
            ],
        )
        self.assertNotIn("max-parallel", architectures["strategy"])
        self.assertNotIn("continue-on-error", architectures)
        self.assertTrue(all("continue-on-error" not in step for step in architectures["steps"]))
        aggregate = jobs["integration"]
        self.assertEqual(aggregate["name"], "Integration")
        self.assertEqual(aggregate["needs"], ["architectures"])
        self.assertEqual(aggregate["if"], "always()")
        step = aggregate["steps"][0]
        self.assertEqual(step["env"]["ARCHITECTURES_RESULT"], "${{ needs.architectures.result }}")
        for result in ("success", "failure", "cancelled", "skipped", ""):
            completed = subprocess.run(
                ["bash", "-c", step["run"]],
                env=dict(os.environ, ARCHITECTURES_RESULT=result),
                check=False,
            )
            self.assertEqual(completed.returncode == 0, result == "success")
        self.assertIn("integration", jobs["weekly-failure"]["needs"])
        self.assertIn("needs.integration.result == 'failure'", jobs["weekly-failure"]["if"])

    def test_canary_only_accepts_exact_decoder_failure(self):
        def fail():
            raise OSError(DECODER_ERROR)

        self.assertEqual(encoding_read(fail)["status"], "expected-failure")
        for exc in (
            OSError("Forbidden"),
            RuntimeError(DECODER_ERROR),
            OSError(DECODER_ERROR + " extra"),
        ):
            with self.subTest(exc=exc), self.assertRaises(type(exc)):
                encoding_read(lambda: (_ for _ in ()).throw(exc))

    def test_canary_success_requires_exact_rows_and_surfaces_fix(self):
        self.assertEqual(encoding_read(lambda: EXPECTED_ROWS)["status"], "upstream-fixed")
        for rows in ([], EXPECTED_ROWS[:1], EXPECTED_ROWS + EXPECTED_ROWS):
            with self.assertRaises(AssertionError):
                encoding_read(lambda: rows)

    def test_redaction_includes_embedded_and_overlapping_credentials(self):
        self.assertEqual(
            redact("url:secret-long@host secret", ["secret", "secret-long"]),
            "url:[REDACTED]@host [REDACTED]",
        )

    def test_remote_canary_rejects_other_failures(self):
        from botocore.exceptions import ClientError

        def error(operation="HeadObject", code="403", message="Forbidden", status=403):
            exc = PermissionError(message)
            exc.__cause__ = ClientError(
                {
                    "Error": {"Code": code, "Message": message},
                    "ResponseMetadata": {"HTTPStatusCode": status},
                },
                operation,
            )
            return exc

        remote_signing_failure(error(), "HeadObject", "403", "Forbidden")
        for exc in (
            error(operation="GetObject"),
            error(code="SignatureDoesNotMatch"),
            error(message="Access Denied."),
            error(status=500),
            PermissionError("Forbidden"),
            OSError("Forbidden"),
        ):
            with self.subTest(exc=exc), self.assertRaises(AssertionError):
                remote_signing_failure(exc, "HeadObject", "403", "Forbidden")

    def test_remote_diagnostics_redact_signatures_and_bearer_tokens(self):
        raw = (
            "Credential=fixture-key/20261111/local/s3/aws4_request, "
            "SignedHeaders=host;x-amz-date, Signature="
            + "a" * 64
            + " Calculated: "
            + "b" * 64
            + ", Provided: "
            + "c" * 64
            + " Authorization: Bearer private-token fixture-secret"
        )
        safe = sanitize(raw, ["fixture-key", "fixture-secret"])
        for secret in (
            "fixture-key",
            "fixture-secret",
            "private-token",
            "a" * 64,
            "b" * 64,
            "c" * 64,
        ):
            self.assertNotIn(secret, safe)
        self.assertIn("SignedHeaders=host;x-amz-date", safe)
        self.assertIn("/20261111/local/s3/aws4_request", safe)

    def test_runtime_must_join_only_the_private_network(self):
        item = {
            "Config": {"User": "1000:0"},
            "HostConfig": {
                "ReadonlyRootfs": True,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "PortBindings": {},
            },
            "NetworkSettings": {"Networks": {"lakehouse-integration_private": {}}},
        }
        check_container_config(item)
        for networks in ({}, {"bridge": {}}, {"lakehouse-integration_private": {}, "bridge": {}}):
            with self.subTest(networks=networks), self.assertRaises(AssertionError):
                check_container_config({**item, "NetworkSettings": {"Networks": networks}})

    def test_compose_isolation_including_setup_containers(self):
        compose = yaml.safe_load(Path("integration/compose.yaml").read_text())
        self.assertTrue(compose["networks"]["private"]["internal"])
        for name, service in compose["services"].items():
            with self.subTest(service=name):
                self.assertTrue(service["read_only"])
                self.assertEqual(service["cap_drop"], ["ALL"])
                self.assertEqual(service["security_opt"], ["no-new-privileges:true"])
                self.assertEqual(service["networks"], ["private"])
                self.assertNotIn(service["user"].split(":")[0], ("", "root", "0"))
                self.assertFalse(service.get("ports"))
        self.assertEqual(compose["services"]["s3"]["volumes"], ["../.runtime/s3:/run/secrets:ro"])
        for name, service in compose["services"].items():
            if name != "postgres":
                self.assertFalse(
                    any(".runtime/postgres" in mount for mount in service.get("volumes", []))
                )


if __name__ == "__main__":
    unittest.main()
