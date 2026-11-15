"""T10: real Sail interoperability and passive evidence of its credential path."""

import json
import os
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TRINO = [[1, "alpha"], [2, "updated"]]
PYTHON = [[10, "py-alpha"], [20, "py-beta"]]
INSERTED = [[100, "sail-alpha"], [200, "sail-beta"], [300, "sail-gamma"]]
UPDATED = [[100, "sail-alpha"], [200, "sail-updated"], [300, "sail-gamma"]]
FINAL = [[100, "sail-alpha"], [200, "sail-updated"]]


def proxy_handshake(h):
    """Verified TLS + HTTP/2 ALPN to the Sail proxy, as the Spark client negotiates."""
    context = h.tls_context()
    context.set_alpn_protocols(["h2"])
    with socket.create_connection(("sail", 50051), timeout=5) as raw:
        with context.wrap_socket(raw, server_hostname="sail") as secure:
            return secure.selected_alpn_protocol() == "h2"


def ready(h):
    h.wait("Sail TLS proxy", lambda: proxy_handshake(h))
    h.wait(
        "Sail",
        lambda: (
            subprocess.run(
                h.DC
                + [
                    "exec",
                    "-T",
                    "sail",
                    "/usr/bin/python3.12",
                    "-I",
                    "-B",
                    "/opt/sail/healthcheck.py",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ),
    )


def queries(h, statements):
    result = subprocess.run(
        [str(h.ROOT / ".sources/sail-venv/bin/python"), str(h.ROOT / "integration/sail_client.py")],
        input=json.dumps(statements),
        text=True,
        capture_output=True,
        timeout=180,
    )
    print(result.stdout, flush=True)
    print(result.stderr, file=sys.stderr, flush=True)
    result.check_returncode()
    return json.loads(
        next(
            line.removeprefix("SAIL_RESULT=")
            for line in result.stdout.splitlines()
            if line.startswith("SAIL_RESULT=")
        )
    )


def independent_read(h, rows):
    # A new process, RestCatalog, FileIO and scan at every mutation boundary.
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve())],
        input=json.dumps(rows),
        text=True,
        capture_output=True,
        timeout=90,
    )
    print(result.stdout, flush=True)
    print(result.stderr, file=sys.stderr, flush=True)
    result.check_returncode()
    return json.loads(result.stdout)


def check_rows(h, rows):
    assert h.sql("SELECT id, label FROM iceberg.integration.from_sail ORDER BY id") == rows
    return independent_read(h, rows)


def interoperability(h):
    """Observe Sail's real catalog calls and S3 signing identity without decrypting TLS.

    The catalog proxy forwards to Lakekeeper over loopback inside the catalog's own
    network namespace (the owner-approved plaintext exception). Capturing that
    loopback hop shows each request exactly as Lakekeeper receives it, including the
    proxy's X-Forwarded-For with the real client address. SeaweedFS's own log records
    which configured identity signed each S3 request; only Sail holds the "sail" key.
    Cleanup redacts credentials before artifact upload. The engine and proxy are not
    patched, and no request is rewritten.
    """
    item = json.loads(subprocess.check_output(["docker", "inspect", h.cid("sail")]))[0]
    address = item["NetworkSettings"]["Networks"]["lakehouse-integration_private"]["IPAddress"]
    catalog_pid = str(
        json.loads(subprocess.check_output(["docker", "inspect", h.cid("catalog")]))[0]["State"][
            "Pid"
        ]
    )
    traffic = h.REPORTS / "sail-traffic.log"
    capture_log = h.REPORTS / "sail-capture.log"
    since = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    with traffic.open("w") as out, capture_log.open("w") as err:
        capture = subprocess.Popen(
            [
                "sudo",
                "nsenter",
                f"--net=/proc/{catalog_pid}/ns/net",
                "tcpdump",
                "-i",
                "lo",
                "-l",
                "-A",
                "-s",
                "0",
                "tcp port 8182",
            ],
            stdout=out,
            stderr=err,
        )
        try:
            h.wait("Sail traffic capture", lambda: "listening on" in capture_log.read_text(), 15)
            result = exercise(h)
            # Wait for the final HTTP exchange to be flushed by line-buffered tcpdump.
            h.wait(
                "captured Sail REST requests",
                lambda: sail_requests(traffic.read_text(), address),
                15,
            )
        finally:
            subprocess.run(["sudo", "kill", "-INT", str(capture.pid)], check=True)
            assert capture.wait(timeout=15) == 0, capture_log.read_text()
    assert "0 packets dropped by kernel" in capture_log.read_text(), capture_log.read_text()
    time.sleep(1)  # Let the gateway flush its final request log lines.
    logs = subprocess.run(
        ["docker", "logs", "--since", since, h.cid("s3")],
        capture_output=True,
        text=True,
        check=True,
    )
    s3_log = logs.stdout + logs.stderr
    (h.REPORTS / "sail-s3-identities.log").write_text(
        "\n".join(line for line in s3_log.splitlines() if "for identity" in line) + "\n"
    )
    result["wire"] = wire_evidence(traffic.read_text(), address, s3_log)
    return result


def sail_requests(trace, address):
    """HTTP requests on the loopback hop that the proxy attributes to Sail."""
    request_line = r"\b(?:GET|POST|HEAD|DELETE|PUT) /[^ \r\n]* HTTP/1\.[01]"
    starts = [m.start() for m in re.finditer(request_line, trace)]
    bounds = [*starts, len(trace)]
    blocks = [trace[a:b] for a, b in zip(bounds, bounds[1:])]
    # tcpdump -A prints each header line's CR as "." before the newline.
    marker = re.compile(r"(?im)^x-forwarded-for: " + re.escape(address) + r"(?:\r|\.)?$")
    return [block for block in blocks if marker.search(block)]


def wire_evidence(trace, address, s3_log):
    requests = sail_requests(trace, address)
    assert requests, "No Sail catalog request captured"
    assert any("x-iceberg-access-delegation: vended-credentials" in r.lower() for r in requests)
    posts = [re.match(r"POST ([^ \r\n]+)", r).group(1) for r in requests if r.startswith("POST")]
    assert posts, "No Sail catalog commit captured"
    assert not any("/sign" in path for path in posts), posts
    # Sail's credential path: its own static key, as recorded by the S3 gateway.
    assert re.search(r"Found access key \S+ for identity sail\b", s3_log), (
        "No Sail-signed S3 request"
    )
    assert "session token" not in s3_log.lower(), "Unexpected STS session credentials"
    return {
        "delegation": "vended-credentials (observed on the catalog's loopback hop, from Sail's address)",
        "s3_authorization": "SigV4 with Sail's own static key (identity 'sail' in the S3 gateway log)",
        "signer_posts": 0,
        "sail_catalog_requests": len(requests),
        "trace": "sail-traffic.log (redacted, catalog namespace loopback only)",
    }


def exercise(h):
    warehouse = h.RESULTS["warehouse"]["response"]["warehouse-id"]
    status, response = h.http(
        "GET",
        f"https://catalog:8181/catalog/v1/{warehouse}/namespaces/integration/tables/from_trino",
        headers={"X-Iceberg-Access-Delegation": "vended-credentials"},
    )
    assert status == 200, (status, response)
    config = response.get("config", {})
    storage = response["storage-credentials"]
    assert len(storage) == 1 and storage[0]["prefix"] == response["metadata"]["location"], storage
    for properties in [config, storage[0]["config"]]:
        assert not any(
            key in properties
            for key in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token")
        ), properties
    assert config["s3.signer"] == "S3V4RestSigner", config
    assert config["s3.remote-signing-enabled"] == "true", config
    h.record(
        "sail_vended_response", {"status": status, "config": config, "storage-credentials": storage}
    )
    assert (
        queries(
            h,
            [
                "CREATE TABLE qualification.integration.from_sail (id BIGINT, label STRING) USING iceberg "
                "TBLPROPERTIES ('format-version'='2', 'write.update.mode'='copy-on-write', 'write.delete.mode'='copy-on-write')",
                "INSERT INTO qualification.integration.from_sail VALUES (100, 'sail-alpha'), (200, 'sail-beta'), (300, 'sail-gamma')",
                "SELECT id, label FROM qualification.integration.from_sail ORDER BY id",
            ],
        )[-1]
        == INSERTED
    )
    stages = {"insert": check_rows(h, INSERTED)}
    assert queries(
        h,
        [
            "SELECT id, label FROM qualification.integration.from_trino ORDER BY id",
            "SELECT id, label FROM qualification.integration.from_python ORDER BY id",
        ],
    ) == [TRINO, PYTHON]
    assert (
        queries(
            h,
            [
                "UPDATE qualification.integration.from_sail SET label='sail-updated' WHERE id=200",
                "SELECT id, label FROM qualification.integration.from_sail ORDER BY id",
            ],
        )[-1]
        == UPDATED
    )
    stages["update"] = check_rows(h, UPDATED)
    assert (
        queries(
            h,
            [
                "DELETE FROM qualification.integration.from_sail WHERE id=300",
                "SELECT id, label FROM qualification.integration.from_sail ORDER BY id",
            ],
        )[-1]
        == FINAL
    )
    stages["delete"] = check_rows(h, FINAL)
    assert len({stage["snapshot"] for stage in stages.values()}) == 3, stages
    return {
        "stages": stages,
        "sail_reads_trino": TRINO,
        "sail_reads_pyiceberg": PYTHON,
        "trino_delta_length_encoding": False,
        "vended_response": config,
    }


def verify_restart(h):
    before = queries(
        h,
        [
            "SELECT id, label FROM qualification.integration.from_sail ORDER BY id",
            "SELECT id, label FROM qualification.integration.from_trino ORDER BY id",
            "SELECT id, label FROM qualification.integration.from_python ORDER BY id",
            "SELECT id, label FROM qualification.integration.encoding_canary ORDER BY id",
        ],
    )
    assert before == [FINAL, TRINO, PYTHON + [[30, "after-restart"]], TRINO], before
    check_rows(h, FINAL)
    after = FINAL + [[400, "sail-after-restart"]]
    assert (
        queries(
            h,
            [
                "INSERT INTO qualification.integration.from_sail VALUES (400, 'sail-after-restart')",
                "SELECT id, label FROM qualification.integration.from_sail ORDER BY id",
            ],
        )[-1]
        == after
    )
    return {"reread_all_tables": before, "new_sail_write": check_rows(h, after)}


def secret_isolation(h):
    item = json.loads(subprocess.check_output(["docker", "inspect", h.cid("sail")]))[0]
    assert item["Config"]["User"] == "10001:10001"
    binds = {m["Destination"]: m for m in item["Mounts"] if m["Type"] == "bind"}
    assert set(binds) == {"/etc/sail/config.json", "/run/tls"}, binds
    assert not any(m["RW"] for m in binds.values())
    assert (
        Path(binds["/etc/sail/config.json"]["Source"]).resolve()
        == (h.ROOT / "integration/sail/config.json").resolve()
    )
    # Public trust only; never a key or another service's directory.
    assert Path(binds["/run/tls"]["Source"]).resolve() == (h.RUNTIME / "tls/trust").resolve()
    env = dict(value.split("=", 1) for value in item["Config"]["Env"])
    assert env["AWS_ACCESS_KEY_ID"] == h.CREDS["sail_access"]
    assert env["AWS_SECRET_ACCESS_KEY"] == h.CREDS["sail_secret"]
    assert env["SSL_CERT_FILE"] == "/run/tls/ca.crt" and env["AWS_ALLOW_HTTP"] == "false"
    assert not any(
        value in json.dumps(item["Config"])
        for key, value in h.CREDS.items()
        if key not in ("sail_access", "sail_secret")
    )
    assert not any(key.startswith(("LAKEKEEPER__", "POSTGRES_", "S3_")) for key in env)
    check = subprocess.run(
        h.DC
        + [
            "exec",
            "-T",
            "sail",
            "/usr/bin/python3.12",
            "-I",
            "-B",
            "-c",
            "from pathlib import Path; assert not Path('/run/secrets').exists()",
        ],
        capture_output=True,
        text=True,
    )
    assert check.returncode == 0, check.stderr
    assert (h.RUNTIME / "sail.env").stat().st_mode & 0o777 == 0o600
    return "Sail-only env_file; its own AWS keys; public CA only; no other secrets or mounts"


if __name__ == "__main__":
    import probe as h

    assert __debug__, "Assertions must be enabled"
    h.CREDS = json.loads((h.RUNTIME / "credentials.json").read_text())
    table = h.rest_catalog().load_table("integration.from_sail")
    expected = json.load(sys.stdin)
    rows = table.scan().to_arrow().sort_by("id").to_pylist()
    assert rows == [dict(zip(("id", "label"), row, strict=True)) for row in expected], rows
    assert table.metadata.format_version == 2
    assert not any(task.delete_files for task in table.scan().plan_files()), (
        "Sail must use copy-on-write"
    )
    assert not table.io.properties.get("s3.signer")
    print(
        json.dumps(
            {
                "rows": rows,
                "snapshot": table.current_snapshot().snapshot_id,
                "delete_files": 0,
                "fresh_process": os.getpid(),
            }
        )
    )
