"""Regression tests for evidence safety, not substitutes for native runtime tests."""

import unittest
from unittest.mock import patch

import common
from scans import counts


class EvidenceSafety(unittest.TestCase):
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
