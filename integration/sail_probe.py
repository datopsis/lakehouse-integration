"""T10: real Sail interoperability and passive evidence of its credential path."""

import json
import os
import subprocess
import sys
from pathlib import Path

TRINO = [[1, "alpha"], [2, "updated"]]
PYTHON = [[10, "py-alpha"], [20, "py-beta"]]
INSERTED = [[100, "sail-alpha"], [200, "sail-beta"], [300, "sail-gamma"]]
UPDATED = [[100, "sail-alpha"], [200, "sail-updated"], [300, "sail-gamma"]]
FINAL = [[100, "sail-alpha"], [200, "sail-updated"]]


def ready(h):
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
    # Capture only T10 traffic; cleanup redacts credentials before artifact upload.
    # Never patch the engine or proxy/rewrite its delegation request.
    item = json.loads(subprocess.check_output(["docker", "inspect", h.cid("sail")]))[0]
    address = item["NetworkSettings"]["Networks"]["lakehouse-integration_private"]["IPAddress"]
    traffic = h.REPORTS / "sail-traffic.log"
    capture_log = h.REPORTS / "sail-capture.log"
    with traffic.open("w") as out, capture_log.open("w") as err:
        capture = subprocess.Popen(
            [
                "sudo",
                "tcpdump",
                "-i",
                "any",
                "-l",
                "-A",
                "-s",
                "0",
                f"host {address} and (tcp port 8181 or tcp port 8333)",
            ],
            stdout=out,
            stderr=err,
        )
        try:
            h.wait("Sail traffic capture", lambda: "listening on" in capture_log.read_text(), 15)
            result = exercise(h)
            # Wait for the final HTTP response to be flushed by line-buffered tcpdump.
            h.wait(
                "captured Sail REST and S3 requests",
                lambda: (
                    "x-iceberg-access-delegation: vended-credentials" in traffic.read_text().lower()
                    and "Credential=" + h.CREDS["access"] + "/" in traffic.read_text()
                ),
                15,
            )
        finally:
            subprocess.run(["sudo", "kill", "-INT", str(capture.pid)], check=True)
            assert capture.wait(timeout=15) == 0, capture_log.read_text()
    assert "0 packets dropped by kernel" in capture_log.read_text(), capture_log.read_text()
    trace = traffic.read_text()
    assert "x-iceberg-access-delegation: vended-credentials" in trace.lower()
    assert "Credential=" + h.CREDS["access"] + "/" in trace
    assert not any("/sign" in line for line in trace.splitlines() if line.startswith("POST "))
    result["wire"] = {
        "delegation": "vended-credentials (observed on wire)",
        "s3_authorization": "AWS SigV4 with fixture's static access key (observed on wire)",
        "signer_posts": 0,
        "trace": "sail-traffic.log (redacted, filtered to Sail container IP)",
    }
    return result


def exercise(h):
    warehouse = h.RESULTS["warehouse"]["response"]["warehouse-id"]
    status, response = h.http(
        "GET",
        f"http://catalog:8181/catalog/v1/{warehouse}/namespaces/integration/tables/from_trino",
        headers={"X-Iceberg-Access-Delegation": "vended-credentials"},
    )
    assert status == 200, (status, response)
    config = response.get("config", {})
    assert not any(
        config.get(key) for key in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token")
    )
    assert not response.get("storage-credentials"), response
    assert any("sign" in key and value for key, value in config.items()), config
    h.record(
        "sail_vended_response", {"status": status, "config": config, "storage-credentials": []}
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
    binds = [m for m in item["Mounts"] if m["Type"] == "bind"]
    assert len(binds) == 1, binds
    assert binds[0]["Destination"] == "/etc/sail/config.json" and not binds[0]["RW"]
    assert Path(binds[0]["Source"]).resolve() == (h.ROOT / "integration/sail/config.json").resolve()
    env = dict(value.split("=", 1) for value in item["Config"]["Env"])
    assert env["AWS_ACCESS_KEY_ID"] == h.CREDS["access"]
    assert env["AWS_SECRET_ACCESS_KEY"] == h.CREDS["secret"]
    assert not any(
        value in json.dumps(item["Config"])
        for key, value in h.CREDS.items()
        if key not in ("access", "secret")
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
    return "Sail-only env_file; exact AWS keys; no other service's secrets or mounts"


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
