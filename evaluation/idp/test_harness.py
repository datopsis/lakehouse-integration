"""Regression tests for evidence safety, not substitutes for native runtime tests."""

import base64
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import catalog
import common
from scans import counts


class EvidenceSafety(unittest.TestCase):
    def test_different_key_tokens_are_well_formed_and_signed(self):
        claims = {
            "iss": "https://issuer.test",
            "aud": "lakekeeper",
            "sub": "test",
            "exp": 2000000000,
        }
        with tempfile.TemporaryDirectory() as tmp:
            for alg in ("RS256", "ES256"):
                header = {"alg": alg, "kid": "real-key-id"}
                original = catalog.b64(header) + "." + catalog.b64(claims) + ".unused"
                provider = SimpleNamespace(name=alg, human_token=original)
                with (
                    patch.object(catalog, "WORK", Path(tmp)),
                    patch.object(catalog, "secret", lambda x: x),
                ):
                    token = catalog.bad_token(provider, "different_key")
                self.assertEqual(common.decode(token), [header, claims])
                content, signature = token.rsplit(".", 1)
                signature = base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4))
                if alg == "ES256":
                    self.assertEqual(len(signature), 64)
                    integers = []
                    for value in (signature[:32], signature[32:]):
                        value = value.lstrip(b"\0") or b"\0"
                        if value[0] >= 128:
                            value = b"\0" + value
                        integers.append(b"\x02" + bytes([len(value)]) + value)
                    value = b"".join(integers)
                    signature = b"\x30" + bytes([len(value)]) + value
                key = Path(tmp) / "forged" / alg / "key.pem"
                public = key.with_suffix(".pub")
                public.write_text(common.run("openssl", "pkey", "-in", key, "-pubout"))
                sigfile = key.with_suffix(".sig")
                sigfile.write_bytes(signature)
                result = subprocess.run(
                    [
                        "openssl",
                        "dgst",
                        "-sha256",
                        "-verify",
                        str(public),
                        "-signature",
                        str(sigfile),
                    ],
                    input=content.encode(),
                    capture_output=True,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_plaintext_is_rejected_before_transport(self):
        client = common.HTTPS("/unused/ca.pem")
        with patch.object(client.session, "request") as request:
            with self.assertRaisesRegex(AssertionError, "HTTPS"):
                client.request("POST", "http://idp/token", data={"client_secret": "test"})
            request.assert_not_called()

    def test_redirects_cannot_forward_credentials(self):
        client = common.HTTPS("/unused/ca.pem")
        with patch.object(client.session, "request") as request:
            client.request("POST", "https://idp/token")
            self.assertFalse(request.call_args.kwargs["allow_redirects"])
            self.assertEqual(client.session.verify, "/unused/ca.pem")
            with self.assertRaises(AssertionError):
                client.request("POST", "https://idp/token", allow_redirects=True)

    def test_private_keys_block_publication(self):
        with self.assertRaisesRegex(AssertionError, "Private key"):
            common.clean("-----BEGIN PRIVATE KEY-----")
        with patch.object(common, "SECRETS", ["generated-password"]):
            self.assertEqual(common.clean("generated-password"), "[REDACTED]")

    def test_only_fixable_high_critical_are_counted(self):
        base = {
            "Severity": "HIGH",
            "PkgName": "pkg",
            "InstalledVersion": "1",
            "VulnerabilityID": "CVE-a",
            "FixedVersion": "2",
        }
        report = {
            "Results": [
                {
                    "Target": "root",
                    "Vulnerabilities": [
                        base,
                        base,
                        {**base, "VulnerabilityID": "CVE-b", "FixedVersion": ""},
                        {**base, "VulnerabilityID": "CVE-c", "Severity": "LOW"},
                        {**base, "VulnerabilityID": "CVE-d", "Severity": "CRITICAL"},
                    ],
                }
            ]
        }
        self.assertEqual(counts("trivy", report), {"HIGH": 1, "CRITICAL": 1})


if __name__ == "__main__":
    unittest.main()
