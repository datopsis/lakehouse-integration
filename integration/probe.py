"""Cross-repository lakehouse assertions. Any unexpected failure fails the run."""

import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".runtime"
REPORTS = ROOT / "reports"
DC = ["docker", "compose", "-f", str(ROOT / "integration/compose.yaml")]
RESULTS = {}
START = time.monotonic()


def record(name, value):
    RESULTS[name] = value
    RESULTS["elapsed_seconds"] = round(time.monotonic() - START, 2)
    (REPORTS / "results.json").write_text(json.dumps(RESULTS, indent=2, default=str) + "\n")
    print(name + ": " + json.dumps(value, default=str), flush=True)


def compose(*args, **kwargs):
    return subprocess.run(DC + list(args), check=True, **kwargs)


def cid(service):
    return subprocess.check_output(DC + ["ps", "-q", service], text=True).strip()


def http(method, url, data=None, headers=None):
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
    elif isinstance(data, str):
        data = data.encode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read()
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()
        try:
            body = json.loads(body)
        except ValueError:
            pass
        return exc.code, body


def wait(label, fn, seconds=120):
    deadline = time.monotonic() + seconds
    error = None
    while time.monotonic() < deadline:
        try:
            if fn():
                return
        except Exception as exc:
            error = str(exc)
        time.sleep(2)
    raise RuntimeError(f"{label} not ready after {seconds}s: {error}")


def hosts():
    # Linux runner can reach the internal bridge. Nothing is port-published.
    entries = []
    for service in ("s3", "catalog", "trino"):
        if not cid(service):
            continue
        item = json.loads(subprocess.check_output(["docker", "inspect", cid(service)]))[0]
        address = next(iter(item["NetworkSettings"]["Networks"].values()))["IPAddress"]
        entries.append(f"{address} {service}\n")
    import re

    old = re.sub(
        r"# lakehouse-integration-start\n.*?# lakehouse-integration-end\n",
        "",
        Path("/etc/hosts").read_text(),
        flags=re.S,
    )
    subprocess.run(
        ["sudo", "tee", "/etc/hosts"],
        input=old
        + "# lakehouse-integration-start\n"
        + "".join(entries)
        + "# lakehouse-integration-end\n",
        text=True,
        stdout=subprocess.DEVNULL,
        check=True,
    )


def sql(query):
    status, page = http(
        "POST", "http://trino:8080/v1/statement", query, {"X-Trino-User": "integration"}
    )
    assert status == 200, (status, page)
    rows = []
    deadline = time.monotonic() + 180
    while True:
        if "error" in page:
            raise RuntimeError(json.dumps(page["error"]))
        rows.extend(page.get("data", []))
        if "nextUri" not in page:
            break
        assert time.monotonic() < deadline, "SQL timeout"
        time.sleep(0.1)
        status, page = http("GET", page["nextUri"])
        assert status == 200, (status, page)
    print("SQL", query, "=>", rows, flush=True)
    return rows


def check_container_config(item):
    config = item["HostConfig"]
    assert item["Config"]["User"].split(":")[0] not in ("0", "root", "")
    assert config["ReadonlyRootfs"] and "ALL" in config["CapDrop"]
    assert "no-new-privileges:true" in config["SecurityOpt"]
    assert not config["PortBindings"]
    assert not config.get("Privileged")
    assert set(item["NetworkSettings"]["Networks"]) == {"lakehouse-integration_private"}


def check_hardening():
    report = {}
    for service in ("postgres", "master", "volume", "filer", "s3", "catalog", "trino"):
        item = json.loads(subprocess.check_output(["docker", "inspect", cid(service)]))[0]
        check_container_config(item)
        status = subprocess.check_output(
            DC + ["exec", "-T", service, "cat", "/proc/1/status"], text=True
        )
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        assert all(int(uid) > 0 for uid in fields["Uid"].split())
        for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
            assert int(fields[field].strip(), 16) == 0, (service, field, fields[field])
        assert fields["NoNewPrivs"].strip() == "1"
        report[service] = {key: fields[key].strip() for key in ("Uid", "CapEff", "NoNewPrivs")}
    net = json.loads(
        subprocess.check_output(["docker", "network", "inspect", "lakehouse-integration_private"])
    )[0]
    assert net["Internal"]
    return report


def rest_catalog(delegation="client-managed", with_credentials=True):
    from pyiceberg.catalog.rest import RestCatalog

    properties = {
        "uri": "http://catalog:8181/catalog",
        "warehouse": "qualification",
        "s3.endpoint": "http://s3:8333",
        "s3.region": "local",
        "s3.path-style-access": "true",
    }
    if with_credentials:
        properties.update(
            {"s3.access-key-id": CREDS["access"], "s3.secret-access-key": CREDS["secret"]}
        )
    if delegation:
        properties["header.X-Iceberg-Access-Delegation"] = delegation
    return RestCatalog("qualification", **properties)


def probe(name, fn):
    start = time.monotonic()
    try:
        value = fn()
        record(
            name, {"status": "pass", "seconds": round(time.monotonic() - start, 2), "value": value}
        )
    except Exception as exc:
        record(
            name,
            {"status": "fail", "seconds": round(time.monotonic() - start, 2), "error": str(exc)},
        )
        traceback.print_exc()


CREDS = {
    key: secrets.token_hex(24)
    for key in ("admin", "postgres", "encryption", "access", "secret", "wrong")
}


def prepare():
    RUNTIME.mkdir(mode=0o755)
    secret_dir = RUNTIME / "postgres"
    secret_dir.mkdir(mode=0o755)
    (RUNTIME / "s3").mkdir(mode=0o755)
    (RUNTIME / "credentials.json").write_text(json.dumps(CREDS))
    (RUNTIME / "credentials.json").chmod(0o600)
    for key in CREDS.values():
        print(f"::add-mask::{key}", flush=True)
    (secret_dir / "postgres-password").write_text(CREDS["admin"])
    (secret_dir / "lakekeeper-password").write_text(CREDS["postgres"])
    (RUNTIME / "s3/s3.json").write_text(
        json.dumps(
            {
                "identities": [
                    {
                        "name": "lakehouse",
                        "credentials": [
                            {"accessKey": CREDS["access"], "secretKey": CREDS["secret"]}
                        ],
                        "actions": ["Read:warehouse", "Write:warehouse", "List:warehouse"],
                    }
                ]
            }
        )
    )
    for directory in (secret_dir, RUNTIME / "s3"):
        subprocess.run(["sudo", "chown", "root:root", str(directory)], check=True)
        subprocess.run(["sudo", "chmod", "0755", str(directory)], check=True)
    for path in [*secret_dir.iterdir(), RUNTIME / "s3/s3.json"]:
        subprocess.run(["sudo", "chown", "root:root", str(path)], check=True)
        subprocess.run(["sudo", "chmod", "0440", str(path)], check=True)
    (RUNTIME / "lakekeeper.env").write_text(
        f"LAKEKEEPER__PG_DATABASE_URL_WRITE=postgres://lakekeeper:{CREDS['postgres']}@postgres:5432/lakekeeper\n"
        f"LAKEKEEPER__PG_ENCRYPTION_KEY={CREDS['encryption']}\n"
    )
    (RUNTIME / "trino.env").write_text(
        f"S3_ACCESS_KEY_ID={CREDS['access']}\nS3_SECRET_ACCESS_KEY={CREDS['secret']}\n"
    )
    for name in ("lakekeeper.env", "trino.env"):
        (RUNTIME / name).chmod(0o600)
    shutil.copytree(ROOT / "integration/trino", RUNTIME / "trino")
    # No encoding override in this catalog: exercise the actual Trino default.
    content = (RUNTIME / "trino/catalog/iceberg.properties").read_text()
    (RUNTIME / "trino/catalog/canary.properties").write_text(
        "\n".join(
            line
            for line in content.splitlines()
            if not line.startswith("parquet.writer.delta-length-byte-array-encoding-enabled=")
        )
        + "\n"
    )

    for path in (RUNTIME / "trino").rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    (RUNTIME / "trino").chmod(0o755)


def start():
    compose("up", "-d", "postgres", "master", "volume", "filer", "s3")
    wait(
        "PostgreSQL TCP",
        lambda: (
            subprocess.run(
                DC
                + [
                    "exec",
                    "-T",
                    "postgres",
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    "postgres",
                    "-d",
                    "lakekeeper",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ),
    )
    with (ROOT / "integration/postgres-init.sql").open() as source:
        compose(
            "exec",
            "-T",
            "postgres",
            "psql",
            "-X",
            "-h",
            "/tmp",
            "-U",
            "postgres",
            "-d",
            "lakekeeper",
            stdin=source,
        )
    migration = "lakehouse-integration-migration"
    try:
        compose("run", "--name", migration, "--no-deps", "migrate")
        check_container_config(
            json.loads(subprocess.check_output(["docker", "inspect", migration]))[0]
        )
    finally:
        subprocess.run(["docker", "rm", "-f", migration], check=True, stdout=subprocess.DEVNULL)
    compose("up", "-d", "catalog")
    hosts()
    wait(
        "Lakekeeper",
        lambda: (
            subprocess.run(
                DC + ["exec", "-T", "catalog", "lakekeeper", "healthcheck", "-s"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ),
    )

    # The hardened gateway disables auto-create. Register the bucket before Lakekeeper validates it.
    def bucket():
        result = subprocess.run(
            DC
            + ["exec", "-T", "master", "weed", "shell", "-master=master:9333", "-filer=filer:8888"],
            input="s3.bucket.create -name warehouse\ns3.bucket.list\n",
            text=True,
            capture_output=True,
        )
        return "warehouse" in result.stdout

    wait("registered bucket", bucket)
    status, _ = http(
        "POST", "http://catalog:8181/management/v1/bootstrap", {"accept-terms-of-use": True}
    )
    assert status == 204, status
    profile = {
        "type": "s3",
        "bucket": "warehouse",
        "region": "local",
        "sts-enabled": False,
        "flavor": "s3-compat",
        "endpoint": "http://s3:8333",
        "path-style-access": True,
    }
    warehouse = {
        "warehouse-name": "qualification",
        "storage-profile": profile,
        "storage-credential": {
            "type": "s3",
            "credential-type": "access-key",
            "access-key-id": CREDS["access"],
            "secret-access-key": CREDS["secret"],
        },
    }
    bad = json.loads(json.dumps(warehouse))
    bad["warehouse-name"] = "rejected"
    bad["storage-credential"]["secret-access-key"] = CREDS["wrong"]
    status, body = http("POST", "http://catalog:8181/management/v1/warehouse", bad)
    assert status == 400 and "signature" in json.dumps(body).lower(), (status, body)
    record("wrong_s3_secret", {"status": status, "body": body})
    status, body = http("POST", "http://catalog:8181/management/v1/warehouse", warehouse)
    assert status in (200, 201), (status, body)
    record("warehouse", {"profile": profile, "response": body})
    compose("up", "-d", "trino")
    hosts()
    wait("Trino", lambda: http("GET", "http://trino:8080/v1/info")[1].get("starting") is False, 180)
    probe("T7_hardening", check_hardening)
    return body["warehouse-id"]


def trino_write():
    assert sql("CREATE SCHEMA iceberg.integration") == []
    assert (
        sql(
            "CREATE TABLE iceberg.integration.from_trino (id BIGINT, label VARCHAR) WITH (format='PARQUET', format_version=2)"
        )
        == []
    )
    assert sql(
        "INSERT INTO iceberg.integration.from_trino VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma')"
    ) == [[3]]
    assert sql("SELECT * FROM iceberg.integration.from_trino ORDER BY id") == [
        [1, "alpha"],
        [2, "beta"],
        [3, "gamma"],
    ]
    return "CREATE TABLE / INSERT / SELECT asserted"


def mutate():
    assert sql("UPDATE iceberg.integration.from_trino SET label='updated' WHERE id=2") == [[1]]
    assert sql("DELETE FROM iceberg.integration.from_trino WHERE id=3") == [[1]]
    assert sql("SELECT * FROM iceberg.integration.from_trino ORDER BY id") == [
        [1, "alpha"],
        [2, "updated"],
    ]
    snapshots = sql(
        'SELECT snapshot_id, operation FROM iceberg.integration."from_trino$snapshots" ORDER BY committed_at'
    )
    history = sql(
        'SELECT snapshot_id, is_current_ancestor FROM iceberg.integration."from_trino$history" ORDER BY made_current_at'
    )
    assert [row[1] for row in snapshots] == ["append", "append", "overwrite", "delete"], snapshots
    assert len({row[0] for row in snapshots}) == 4
    assert history == [[row[0], True] for row in snapshots], history
    return {"snapshots": snapshots, "history": history}


def py_read(expected=None, delegation="client-managed", with_credentials=True):
    table = rest_catalog(delegation, with_credentials).load_table("integration.from_trino")
    from pyiceberg.io.pyarrow import PyArrowFileIO

    assert isinstance(table.io, PyArrowFileIO)
    assert not table.io.properties.get("s3.signer")
    rows = table.scan().to_arrow().sort_by("id").to_pylist()
    expected = expected or [{"id": 1, "label": "alpha"}, {"id": 2, "label": "updated"}]
    assert rows == expected, rows
    paths = [task.file.file_path for task in table.scan().plan_files()]
    assert paths and all(p.startswith("s3://warehouse/") for p in paths)
    return {
        "rows": rows,
        "files": paths,
        "file_io": type(table.io).__module__ + "." + type(table.io).__name__,
        "signer": table.io.properties.get("s3.signer"),
        "delegation": delegation,
        "client_s3_credentials": with_credentials,
    }


def py_write():
    import pyarrow as pa

    data = pa.table({"id": [10, 20], "label": ["py-alpha", "py-beta"]})
    table = rest_catalog().create_table(
        "integration.from_python", schema=data.schema, properties={"format-version": "2"}
    )
    table.append(data)
    assert sql("SELECT * FROM iceberg.integration.from_python ORDER BY id") == [
        [10, "py-alpha"],
        [20, "py-beta"],
    ]
    return {"metadata": table.metadata_location, "rows": 2}


def restart():
    old = {
        service: cid(service)
        for service in ("postgres", "master", "volume", "filer", "s3", "catalog", "trino")
    }
    # Down removes every container and network, retaining only named volumes and secrets.
    logs = subprocess.run(DC + ["logs", "--no-color"], text=True, capture_output=True, check=True)
    (REPORTS / "services-before-recreation.log").write_text(logs.stdout + logs.stderr)
    compose("down", "--timeout", "30")
    compose("up", "-d")
    hosts()
    wait(
        "catalog after restart",
        lambda: (
            subprocess.run(
                DC + ["exec", "-T", "catalog", "lakekeeper", "healthcheck", "-s"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ).returncode
            == 0
        ),
    )
    wait(
        "Trino after restart",
        lambda: http("GET", "http://trino:8080/v1/info")[1].get("starting") is False,
        180,
    )
    new = {service: cid(service) for service in old}
    assert all(
        previous and new[service] and new[service] != previous for service, previous in old.items()
    )
    record("container_recreation", {"before": old, "after": new})
    # A fresh independent reader matches the owner's storage fixture and avoids
    # carrying S3/signing/DNS clients across network/container replacement.
    checked = subprocess.run(
        [sys.executable, __file__, "verify-restart"], text=True, capture_output=True
    )
    print(checked.stdout, flush=True)
    print(checked.stderr, file=sys.stderr, flush=True)
    checked.check_returncode()
    check_hardening()
    return json.loads(
        next(
            line.removeprefix("RESTART_RESULT=")
            for line in checked.stdout.splitlines()
            if line.startswith("RESTART_RESULT=")
        )
    )


def verify_restart():
    assert sql("SELECT * FROM iceberg.integration.from_trino ORDER BY id") == [
        [1, "alpha"],
        [2, "updated"],
    ]
    assert sql("SELECT * FROM iceberg.integration.from_python ORDER BY id") == [
        [10, "py-alpha"],
        [20, "py-beta"],
    ]
    py_read()
    assert rest_catalog().load_table("integration.from_python").scan().to_arrow().sort_by(
        "id"
    ).to_pylist() == [{"id": 10, "label": "py-alpha"}, {"id": 20, "label": "py-beta"}]
    assert sql("SELECT * FROM canary.integration.encoding_canary ORDER BY id") == [
        [1, "alpha"],
        [2, "updated"],
    ]
    canary_outcome = canary_read()
    assert sql("INSERT INTO iceberg.integration.from_python VALUES (30, 'after-restart')") == [[1]]
    assert rest_catalog().load_table("integration.from_python").scan().to_arrow().sort_by(
        "id"
    ).to_pylist() == [
        {"id": 10, "label": "py-alpha"},
        {"id": 20, "label": "py-beta"},
        {"id": 30, "label": "after-restart"},
    ]
    result = {
        "static_mode": "Both engines reread main tables; new Trino write read by PyIceberg",
        "encoding_canary": canary_outcome,
    }
    print("RESTART_RESULT=" + json.dumps(result), flush=True)


def canary_read():
    from gates import encoding_read

    outcome = encoding_read(
        lambda: (
            rest_catalog()
            .load_table("integration.encoding_canary")
            .scan()
            .to_arrow()
            .sort_by("id")
            .to_pylist()
        )
    )
    if outcome["status"] == "upstream-fixed":
        notice = "Upstream fixed the Arrow DeltaLengthByteArray decoder; revisit and remove the Trino encoding setting after review."
        print("::notice title=Encoding canary passed::" + notice, flush=True)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                summary.write("\n**Encoding canary passed: " + notice + "**\n")
    return outcome


def canary():
    sql(
        "CREATE TABLE canary.integration.encoding_canary (id BIGINT, label VARCHAR) WITH (format='PARQUET', format_version=2)"
    )
    assert sql(
        "INSERT INTO canary.integration.encoding_canary VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma')"
    ) == [[3]]
    assert sql("SELECT * FROM canary.integration.encoding_canary ORDER BY id") == [
        [1, "alpha"],
        [2, "beta"],
        [3, "gamma"],
    ]
    assert rest_catalog().load_table("integration.encoding_canary").scan().to_arrow().sort_by(
        "id"
    ).to_pylist() == [
        {"id": 1, "label": "alpha"},
        {"id": 2, "label": "beta"},
        {"id": 3, "label": "gamma"},
    ]
    assert sql("UPDATE canary.integration.encoding_canary SET label='updated' WHERE id=2") == [[1]]
    assert sql("DELETE FROM canary.integration.encoding_canary WHERE id=3") == [[1]]
    assert sql("SELECT * FROM canary.integration.encoding_canary ORDER BY id") == [
        [1, "alpha"],
        [2, "updated"],
    ]
    # Confirm this is a positional-delete scan, not a vacuous canary.
    table = rest_catalog().load_table("integration.encoding_canary")
    assert any(task.delete_files for task in table.scan().plan_files())
    return canary_read()


def s3_client(secret=None, anonymous=False):
    import botocore.session
    from botocore import UNSIGNED
    from botocore.config import Config

    return botocore.session.get_session().create_client(
        "s3",
        endpoint_url="http://s3:8333",
        region_name="local",
        aws_access_key_id=CREDS["access"],
        aws_secret_access_key=secret or CREDS["secret"],
        config=Config(
            signature_version=UNSIGNED if anonymous else "s3v4",
            s3={"addressing_style": "path"},
            retries={"max_attempts": 0},
            connect_timeout=5,
            read_timeout=15,
        ),
    )


def location():
    from pyiceberg.manifest import FileFormat

    client = s3_client()
    objects = {
        obj["Key"]
        for page in client.get_paginator("list_objects_v2").paginate(Bucket="warehouse")
        for obj in page.get("Contents", [])
    }
    evidence = {}
    for name in ("from_trino", "from_python", "encoding_canary"):
        table = rest_catalog().load_table("integration." + name)
        assert table.metadata.format_version == 2
        files = list(table.scan().plan_files())
        assert files and all(task.file.file_format == FileFormat.PARQUET for task in files)
        paths = [table.metadata_location] + [task.file.file_path for task in files]
        paths += [file.file_path for task in files for file in task.delete_files]
        for path in paths:
            assert path.startswith("s3://warehouse/"), path
            key = path.removeprefix("s3://warehouse/")
            assert key in objects, key
            assert client.head_object(Bucket="warehouse", Key=key)["ContentLength"] > 0
        evidence[name] = paths
    rows = subprocess.check_output(
        DC
        + [
            "exec",
            "-T",
            "postgres",
            "psql",
            "-X",
            "-h",
            "/tmp",
            "-U",
            "postgres",
            "-d",
            "lakekeeper",
            "-At",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "SELECT name FROM tabular WHERE typ='table' ORDER BY name",
        ],
        text=True,
    ).splitlines()
    assert rows == ["encoding_canary", "from_python", "from_trino"], rows
    return {"objects": len(objects), "tables": evidence, "postgres_catalog_rows": rows}


def secret_isolation():
    item = json.loads(subprocess.check_output(["docker", "inspect", cid("s3")]))[0]
    mounts = [m for m in item["Mounts"] if m["Type"] == "bind"]
    assert len(mounts) == 1 and mounts[0]["Destination"] == "/run/secrets" and not mounts[0]["RW"]
    assert Path(mounts[0]["Source"]).resolve() == (RUNTIME / "s3").resolve()
    listing = subprocess.check_output(
        DC + ["exec", "-T", "s3", "ls", "-A", "/run/secrets"], text=True
    )
    assert listing.splitlines() == ["s3.json"], listing
    for name in ("postgres-password", "lakekeeper-password"):
        result = subprocess.run(
            DC + ["exec", "-T", "s3", "cat", "/run/secrets/" + name], capture_output=True
        )
        assert result.returncode != 0 and b"No such file" in result.stderr, result.stderr
    # An environment leak is as serious as a mount leak.
    for service in ("master", "volume", "filer", "s3", "trino"):
        config = json.loads(subprocess.check_output(["docker", "inspect", cid(service)]))[0][
            "Config"
        ]
        assert all(value not in json.dumps(config) for value in (CREDS["admin"], CREDS["postgres"]))
    return "S3 sees only s3.json; PostgreSQL passwords are absent and unreadable"


def negatives():
    from botocore.exceptions import ClientError

    outcomes = {}
    for name, client, code in (
        ("anonymous_s3", s3_client(anonymous=True), "AccessDenied"),
        ("wrong_s3_secret", s3_client(secret=CREDS["wrong"]), "SignatureDoesNotMatch"),
    ):
        try:
            client.list_objects_v2(Bucket="warehouse")
        except ClientError as exc:
            assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 403, exc
            assert exc.response["Error"]["Code"] == code, exc
            outcomes[name] = code
        else:
            raise AssertionError(name + " was accepted")
    for name, overrides, expected in (
        (
            "missing_encryption_key",
            {"LAKEKEEPER__PG_ENCRYPTION_KEY": ""},
            "LAKEKEEPER__PG_ENCRYPTION_KEY is unset or empty",
        ),
        (
            "wrong_postgres_password",
            {
                "LAKEKEEPER__PG_DATABASE_URL_WRITE": f"postgres://lakekeeper:{CREDS['wrong']}@postgres:5432/lakekeeper"
            },
            "password authentication failed",
        ),
    ):
        container = "lakehouse-integration-negative-" + name
        args = DC + ["run", "--name", container, "--no-deps"]
        for key in overrides:
            args += ["-e", key]  # Values come from the environment, never argv.
        args += ["migrate", "serve" if name == "missing_encryption_key" else "migrate"]
        try:
            result = subprocess.run(
                args, env=dict(os.environ, **overrides), text=True, capture_output=True, timeout=90
            )
            check_container_config(
                json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
            )
            log = result.stdout + result.stderr
            (REPORTS / (name + ".log")).write_text(log)
            assert result.returncode != 0 and expected in log, (name, result.returncode, log)
            if name == "missing_encryption_key":
                assert result.returncode == 78, result.returncode
            outcomes[name] = {"exit_code": result.returncode, "matched": expected}
        finally:
            subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)
    return outcomes


def main():
    global CREDS
    if not __debug__:
        raise RuntimeError("Assertions must be enabled; remove -O/PYTHONOPTIMIZE")
    if sys.argv[1:] == ["verify-restart"]:
        CREDS = json.loads((RUNTIME / "credentials.json").read_text())
        verify_restart()
        return
    REPORTS.mkdir(exist_ok=True)
    try:
        prepare()
        start()
        probe("T1_create_insert_select", trino_write)
        probe(
            "T2_pyiceberg_before_mutations",
            lambda: py_read(
                [
                    {"id": 1, "label": "alpha"},
                    {"id": 2, "label": "beta"},
                    {"id": 3, "label": "gamma"},
                ]
            ),
        )
        probe("T1_update_delete_history", mutate)
        probe("T2_pyiceberg_after_mutations", py_read)
        probe("T3_trino_reads_pyiceberg", py_write)
        probe("encoding_canary", canary)
        probe("T4_location", location)
        probe("T6_negative", negatives)
        probe("T7_secret_isolation", secret_isolation)
        probe("T5_persistence", restart)
    except Exception as exc:
        record("fatal", {"status": "fail", "error": str(exc)})
        traceback.print_exc()
    finally:
        record("total_runtime_seconds", round(time.monotonic() - START, 2))
    expected = {
        "T1_create_insert_select",
        "T1_update_delete_history",
        "T2_pyiceberg_before_mutations",
        "T2_pyiceberg_after_mutations",
        "T3_trino_reads_pyiceberg",
        "T4_location",
        "T5_persistence",
        "T6_negative",
        "T7_hardening",
        "T7_secret_isolation",
        "encoding_canary",
    }
    assert expected <= RESULTS.keys(), "Missing tests: " + str(expected - RESULTS.keys())
    assert not any(isinstance(v, dict) and v.get("status") == "fail" for v in RESULTS.values()), (
        "See reports/results.json"
    )


if __name__ == "__main__":
    main()
