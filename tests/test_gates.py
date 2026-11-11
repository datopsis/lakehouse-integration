"""Regression tests for gates that must never accidentally turn a failure green."""

import copy
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
from build import provenance_errors
from gates import DECODER_ERROR, EXPECTED_ROWS, encoding_read, redact, remote_signing_failure
from probe import check_container_config
from remote_signing import sanitize


class Gates(unittest.TestCase):
    def test_exact_provenance(self):
        image = {
            "Architecture": "amd64",
            "Config": {
                "Labels": {
                    "org.opencontainers.image.revision": "a" * 40,
                    "io.datopsis.artifact-lock.sha256": "b" * 64,
                }
            },
        }
        self.assertEqual(provenance_errors(image, "a" * 40, "b" * 64), [])
        for field in image["Config"]["Labels"]:
            for value in (None, "", "wrong"):
                with self.subTest(field=field, value=value):
                    broken = copy.deepcopy(image)
                    broken["Config"]["Labels"][field] = value
                    self.assertTrue(provenance_errors(broken, "a" * 40, "b" * 64))
        image["Architecture"] = "arm64"
        self.assertTrue(provenance_errors(image, "a" * 40, "b" * 64))

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
