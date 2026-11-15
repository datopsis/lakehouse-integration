"""Fail-closed checks for the Phase A TLS harness (no containers needed)."""

import re
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
import pki
from tls_checks import (
    CERT_ALERTS,
    CLIENT_PATTERNS,
    EXACT_VERIFY_FAILURE,
    GO_400,
    NGINX_GENERIC_400,
    Matrix,
    classify,
    decode,
    relay_conf,
    scope,
    sqlx_refusal,
    transport_hangup,
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

    def test_transport_close_requires_a_new_matching_connection(self):
        def packet(client="192.0.2.1", source=40000, server="192.0.2.2", port=50051, flags="S"):
            return f"123.123456 IP {client}.{source} > {server}.{port}: Flags [{flags}], length 0\n"

        syn = packet()
        for close in ("F.", "R", "R."):
            self.assertTrue(
                transport_hangup(syn + packet(flags=close), "192.0.2.1", "192.0.2.2", 50051)
            )
        for text in (
            packet(flags="F."),
            syn,
            syn + packet(source=40001, flags="F."),
            syn + packet(client="192.0.2.3", flags="F."),
            syn + packet(server="192.0.2.3", flags="F."),
            syn + packet(port=8333, flags="F."),
            packet(flags="F.") + syn,
        ):
            with self.subTest(text=text):
                self.assertFalse(transport_hangup(text, "192.0.2.1", "192.0.2.2", 50051))

    @patch("tls_checks.time.sleep")
    def test_negative_requires_zero_requests_and_certificate_evidence(self, _sleep):
        relay = Mock()
        relay.recorded_hangup.return_value = False
        matrix = object.__new__(Matrix)
        matrix.relay, matrix.rows = relay, []
        exact = (
            "Certificate for <s3> doesn't match any of the subject alternative names: "
            "[wrong.invalid]"
        )
        cases = [
            (([], [], True), exact, True),
            (([], [42], False), "hostname mismatch", True),
            (([], [], False), exact, False),
            (([], [], True), "hostname mismatch", False),
            (([], [], True), "timed out", False),
            (([], [], True), "certificate verify failed: certificate has expired", False),
            ((["application request"], [42], True), exact, False),
            (([], [80], False), exact, False),
        ]
        for evidence, error, accepted in cases:
            with self.subTest(evidence=evidence, error=error):
                relay.evidence.return_value = evidence

                def call():
                    return False, error

                if accepted:
                    matrix.case("trino-s3->s3", "s3", "wrong-san", call, "192.0.2.1")
                    self.assertEqual(matrix.rows[-1]["detail"]["requests"], 0)
                else:
                    with self.assertRaises(AssertionError):
                        matrix.case("trino-s3->s3", "s3", "wrong-san", call, "192.0.2.1")

    @patch("tls_checks.time.sleep")
    def test_transport_hangup_still_requires_exact_error_and_zero_requests(self, _sleep):
        relay = Mock()
        relay.evidence.return_value = [], [], False
        relay.recorded_hangup.return_value = True
        matrix = object.__new__(Matrix)
        matrix.relay, matrix.rows = relay, []
        exact = "Custom verification check failed with error: UNAUTHENTICATED: Hostname Verification Check failed."
        matrix.case("pyspark-grpc->sail", "sail", "wrong-san", lambda: (False, exact), "192.0.2.1")
        for generic in (
            "timed out",
            "Connection refused",
            "hostname mismatch",
            "HTTP 403 Forbidden",
        ):
            with self.subTest(error=generic), self.assertRaises(AssertionError):
                matrix.case(
                    "pyspark-grpc->sail", "sail", "wrong-san", lambda: (False, generic), "192.0.2.1"
                )
        relay.evidence.return_value = ["application request"], [], False
        with self.assertRaises(AssertionError):
            matrix.case(
                "pyspark-grpc->sail", "sail", "wrong-san", lambda: (False, exact), "192.0.2.1"
            )

    def test_sqlx_hangup_is_attributed_and_certificate_specific(self):
        server = (
            "2026-11-15 [64] LOG:  connection received: host=192.0.2.1 port=40000\n"
            "2026-11-15 [64] LOG:  could not accept SSL connection: unexpected eof while reading\n"
        )
        diagnoses = {
            "wrong-ca": "invalid peer certificate: UnknownIssuer",
            "wrong-san": 'invalid peer certificate: certificate not valid for name "postgres"; certificate is only valid for DnsName("wrong.invalid")',
            "expired": "invalid peer certificate: certificate expired: verification time 1794769661 (UNIX), but certificate is not valid after 1794766061 (3600 seconds ago)",
        }
        for variant, diagnosis in diagnoses.items():
            with self.subTest(variant=variant):
                evidence = sqlx_refusal(variant, diagnosis, server, "192.0.2.1")
                self.assertEqual(evidence["application_requests"], 0)
                self.assertEqual(evidence["probe_connections"], 1)
                for other, message in diagnoses.items():
                    if other != variant:
                        with self.assertRaises(AssertionError):
                            sqlx_refusal(variant, message, server, "192.0.2.1")
        for text in (
            "timed out",
            "invalid peer certificate",
            "password authentication failed",
            "connection closed",
        ):
            with self.subTest(error=text), self.assertRaises(AssertionError):
                sqlx_refusal("wrong-ca", text, server, "192.0.2.1")
        for bad_server in (
            server.replace("192.0.2.1", "192.0.2.2"),
            server.replace("[64] LOG:  could", "[65] LOG:  could"),
            server + "2026-11-15 [64] LOG:  password authentication failed\n",
            server.replace("unexpected eof while reading", "internal error"),
            server.replace("unexpected eof while reading", "tlsv1 alert internal error"),
        ):
            with self.subTest(server=bad_server), self.assertRaises(AssertionError):
                sqlx_refusal("wrong-ca", diagnoses["wrong-ca"], bad_server, "192.0.2.1")

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
        observed = {
            "wrong-ca": [
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: unable to get local issuer certificate",
                "CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate: OK",
                "curlCode: 60, SSL peer certificate or SSH remote key was not OK; Details: SSL certificate "
                "OpenSSL verify result: unable to get local issuer certificate (20)",
            ],
            "wrong-san": [
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: Hostname mismatch, certificate is not valid for 's3'.",
                "Peer name sail is not in peer certificate",
                "Custom verification check failed with error: UNAUTHENTICATED: Hostname Verification Check failed.",
                "javax.net.ssl.SSLPeerUnverifiedException: Certificate for <s3> doesn't match any "
                "of the subject alternative names: [wrong.invalid]",
                "SSL validation failed for https://s3:8333/warehouse hostname 's3' doesn't match 'wrong.invalid'",
                "curlCode: 60, SSL peer certificate or SSH remote key was not OK; Details: SSL: "
                "no alternative certificate subject name matches target hostname",
            ],
            "expired": [
                "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: certificate has expired",
                "OpenSSL verify result: certificate has expired (10)",
                "CERTIFICATE_VERIFY_FAILED: certificate has expired: OK",
            ],
        }
        # Each exact diagnosis identifies only its own mutation.
        for variant, pattern in EXACT_VERIFY_FAILURE.items():
            for other, messages in observed.items():
                for message in messages:
                    with self.subTest(variant=variant, message=message):
                        self.assertEqual(bool(re.search(pattern, message)), variant == other)


if __name__ == "__main__":
    unittest.main()
