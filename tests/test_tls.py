"""Fail-closed checks for the Phase A TLS harness (no containers needed)."""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
import pki
from tls_checks import (
    CERT_ALERTS,
    CLIENT_PATTERNS,
    GO_400,
    NGINX_GENERIC_400,
    POST_HANDSHAKE_NAME_CHECK,
    classify,
    decode,
    relay_conf,
    scope,
)

ROOT = Path(__file__).resolve().parents[1]
# Executable harness, Compose, generated-configuration templates and workflow.
SURFACE = [
    *sorted((ROOT / "integration").rglob("*.py")),
    *sorted((ROOT / "integration").rglob("*.yaml")),
    *sorted((ROOT / "integration").rglob("*.properties")),
    *sorted((ROOT / "integration").rglob("*.json")),
    ROOT / ".github/workflows/integration.yml",
]
DOWNGRADES = [
    r"verify\s*=\s*False",
    r"CERT_NONE",
    r"check_hostname\s*=\s*False",
    r"_create_unverified_context",
    r"(?i)insecure_skip_verify\s*=\s*true",
    r"(?i)InsecureSkipVerify",
    r"danger_accept_invalid",
    r"(?i)AWS_ALLOW_INVALID_CERTIFICATES",
    r"(?i)AWS_ALLOW_HTTP['\"]?\s*[:=]\s*['\"]?true",
    r"(?i)(proxy|grpc)_ssl_verify\s+off",
    r"(?i)sslmode=(disable|allow|prefer|require|verify-ca)\b",
    r"(?i)ssl_target_name_override",
    r"(?:^|\s)(-k|--insecure)(\s|$)",
    r"(?i)trustAll|TrustAllStrategy|NoopHostnameVerifier",
    r"(?i)SSLKEYLOGFILE",
    r"(?i)-port\.https",
    r"http-server\.http\.enabled=true",
]


class TlsGates(unittest.TestCase):
    def test_no_verification_downgrade_anywhere_in_the_surface(self):
        for path in SURFACE:
            text = path.read_text()
            for pattern in DOWNGRADES:
                with self.subTest(path=path.name, pattern=pattern):
                    self.assertIsNone(re.search(pattern, text, re.M), (path, pattern))

    def test_only_https_and_tls_endpoints(self):
        # Exactly one plaintext URL: the probe catalog's loopback backend, reached
        # only from inside that probe's own network namespace.
        for path in SURFACE:
            for match in re.finditer(r"\bhttp://[^\s\"'`]+", path.read_text()):
                with self.subTest(path=path.name, url=match.group(0)):
                    self.assertEqual(path.name, "tls_clients.py")
                    self.assertTrue(match.group(0).startswith("http://127.0.0.1:8182/"))
        for path in SURFACE:
            for match in re.finditer(r"sc://[^\"'\s]+", path.read_text()):
                url = match.group(0)
                with self.subTest(path=path.name, url=url):
                    self.assertTrue(
                        url.endswith(";use_ssl=true") or url.startswith("sc://127.0.0.1:")
                    )
        for line in (
            (ROOT / "integration/trino/catalog/iceberg.properties").read_text().splitlines()
        ):
            if line.startswith(("iceberg.rest-catalog.uri=", "s3.endpoint=")):
                self.assertIn("=https://", line)

    def test_trino_profile_is_https_only(self):
        config = dict(
            line.split("=", 1)
            for line in (ROOT / "integration/trino/config.properties").read_text().splitlines()
            if line and not line.startswith("#")
        )
        self.assertEqual(config["http-server.http.enabled"], "false")
        self.assertEqual(config["http-server.https.enabled"], "true")
        self.assertEqual(config["internal-communication.https.required"], "true")
        self.assertTrue(config["discovery.uri"].startswith("https://trino:8443"))
        self.assertNotIn("internal-communication.shared-secret", config)  # per-run only

    def test_plaintext_classifier_accepts_only_refusals(self):
        nginx = b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n<html>The plain HTTP request was sent to HTTPS port</html>"
        go = b"HTTP/1.0 400 Bad Request\r\n\r\n" + GO_400
        generic = b"HTTP/1.1 400 Bad Request\r\nServer: nginx\r\n\r\n" + NGINX_GENERIC_400
        self.assertEqual(classify(generic)[0], "protocol-error-400")
        self.assertEqual(classify(b"")[0], "closed")
        self.assertEqual(classify(b"\x15\x03\x03\x00\x02\x02\x46")[0], "tls-alert")
        self.assertEqual(classify(nginx)[0], "protocol-error-400")
        self.assertEqual(classify(go)[0], "protocol-error-400")
        for data in (
            b"HTTP/1.1 200 OK\r\n\r\n{}",
            b"HTTP/1.1 400 Bad Request\r\n\r\nsomething else",
            b"HTTP/1.1 301 Moved\r\nLocation: https://x\r\n\r\n",
            b"\x00\x00\x12\x04",  # an HTTP/2 SETTINGS frame: cleartext gRPC answered
            b"\x16\x03\x03",  # a TLS handshake record is not a refusal of plaintext
        ):
            with self.subTest(data=data):
                self.assertEqual(classify(data)[0], "UNEXPECTED")

    def test_socket_inventory_decoding(self):
        self.assertEqual(
            decode("0100007F:1FF6"), (__import__("ipaddress").ip_address("127.0.0.1"), 8182)
        )
        ip, port = decode("00000000000000000000000000000000:1FF5")
        self.assertEqual((scope(ip), port), ("any", 8181))
        ip, _ = decode("0B00007F:A1B2")
        self.assertEqual(scope(ip), "docker-dns")
        ip, _ = decode("0900A8C0:1F90")
        self.assertEqual(scope(ip), "address:192.168.0.9")

    def test_relay_verifies_upstreams_and_never_resumes(self):
        conf = relay_conf()
        for directive in (
            "proxy_ssl_verify on;",
            "grpc_ssl_verify on;",
            "proxy_ssl_server_name on;",
            "ssl_session_cache off;",
            "ssl_session_tickets off;",
            "error_log /dev/stderr info;",
        ):
            self.assertIn(directive, conf)
        self.assertNotIn("http://", conf)
        self.assertEqual(conf.count("listen "), 6)
        self.assertEqual(len(re.findall(r"proxy_pass https://", conf)), 3)
        self.assertIn("grpc_pass grpcs://sail:50051", conf)

    def test_pki_plan_has_explicit_dns_identities_and_isolated_mutations(self):
        plan = {name: rest for name, *rest in pki.plan()}
        self.assertEqual(len(plan), len(pki.plan()), "duplicate leaf names")
        for name, (cn, san, purpose, issuer, expired) in plan.items():
            with self.subTest(leaf=name):
                self.assertTrue(san and "*" not in san)
                self.assertIn(purpose, ("serverAuth", "clientAuth"))
                if name.endswith("-wrong-ca") or name == "untrusted-client":
                    self.assertEqual(issuer, "unrelated")
                else:
                    self.assertEqual(issuer, "ca")
                self.assertEqual(expired, name.endswith("expired") or name == "expired-client")
                if name.endswith("-wrong-san"):
                    self.assertEqual((cn, san), (name.removesuffix("-wrong-san"), pki.WRONG_SAN))
                elif purpose == "serverAuth":
                    self.assertEqual(san, cn)

    def test_negative_oracles_are_certificate_specific(self):
        self.assertEqual(CERT_ALERTS, {42, 43, 44, 45, 46, 48})
        for variant, pattern in CLIENT_PATTERNS.items():
            with self.subTest(variant=variant):
                for unrelated in (
                    "Connection refused",
                    "timed out",
                    "HTTP 403 Forbidden",
                    "AccessDenied",
                ):
                    self.assertIsNone(re.search(pattern, unrelated))
        self.assertTrue(
            re.search(POST_HANDSHAKE_NAME_CHECK, "Peer name sail is not in peer certificate")
        )


if __name__ == "__main__":
    unittest.main()
