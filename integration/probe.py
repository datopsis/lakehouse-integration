"""Cross-repository lakehouse assertions. Any unexpected failure fails the run."""

import json
import os
import secrets
import shutil
import socket
import ssl
import struct
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
# The run's public root. Every runner client and fresh reader verifies against it
# (hostname included). Set before PyArrow/gRPC import; inherited by subprocesses.
CA_FILE = str(RUNTIME / "tls/trust/ca.crt")
for _variable in (
    "SSL_CERT_FILE",  # Python ssl defaults and Arrow's S3 client
    "REQUESTS_CA_BUNDLE",  # Requests-based REST and remote-signing sessions
    "AWS_CA_BUNDLE",  # botocore/aiobotocore (T9 FsspecFileIO)
    "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",  # PySpark Connect channels
):
    os.environ[_variable] = CA_FILE
SERVICES = ("postgres", "master", "volume", "filer", "s3", "catalog", "trino", "sail")
PROXIES = {"catalog-proxy": "catalog", "sail-proxy": "sail"}
DC = [
    "docker",
    "compose",
    "-f",
    str(ROOT / "integration/compose.yaml"),
    "-f",
    str(ROOT / "integration/compose.sail.yaml"),
]
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


class HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise AssertionError(f"Unexpected redirect {code} to {newurl}")


def tls_context(cafile=None):
    context = ssl.create_default_context(cafile=cafile or CA_FILE)
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    return context


def opener():
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        HttpsOnly(),
        urllib.request.HTTPSHandler(context=tls_context()),
    )


def http(method, url, data=None, headers=None):
    assert url.startswith("https://"), "Plaintext URL refused: " + url
    if isinstance(data, (dict, list)):
        data = json.dumps(data).encode()
        headers = {"Content-Type": "application/json", **(headers or {})}
    elif isinstance(data, str):
        data = data.encode()
    request = urllib.request.Request(url, data=data, method=method, headers=headers or {})
    try:
        with opener().open(request, timeout=30) as response:
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


def hosts(overrides=None):
    # Linux runner can reach the internal bridge. Nothing is port-published.
    # overrides: names the TLS negative tests temporarily resolve to their relay.
    entries = []
    for service in SERVICES:
        if not cid(service):
            continue
        item = json.loads(subprocess.check_output(["docker", "inspect", cid(service)]))[0]
        address = next(iter(item["NetworkSettings"]["Networks"].values()))["IPAddress"]
        entries.append(f"{(overrides or {}).get(service, address)} {service}\n")
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


def sql(query, observe=None):
    status, page = http(
        "POST", "https://trino:8443/v1/statement", query, {"X-Trino-User": "integration"}
    )
    assert status == 200, (status, page)
    rows = []
    deadline = time.monotonic() + 180
    while True:
        if observe is not None:
            observe(page)
        if "error" in page:
            raise RuntimeError(json.dumps(page["error"]))
        rows.extend(page.get("data", []))
        if "nextUri" not in page:
            break
        assert time.monotonic() < deadline, "SQL timeout"
        assert page["nextUri"].startswith("https://trino:8443/"), page["nextUri"]
        time.sleep(0.1)
        status, page = http("GET", page["nextUri"])
        assert status == 200, (status, page)
    print("SQL", query, "=>", rows, flush=True)
    return rows


def check_container_config(item, namespace_owner=None):
    """namespace_owner: a proxy must share ONLY that container's network namespace."""
    config = item["HostConfig"]
    assert item["Config"]["User"].split(":")[0] not in ("0", "root", "")
    assert config["ReadonlyRootfs"] and "ALL" in config["CapDrop"]
    assert "no-new-privileges:true" in config["SecurityOpt"]
    assert not config["PortBindings"]
    assert not config.get("Privileged")
    if namespace_owner is None:
        assert set(item["NetworkSettings"]["Networks"]) == {"lakehouse-integration_private"}
    else:
        assert config["NetworkMode"] == "container:" + namespace_owner, config["NetworkMode"]
        assert not item["NetworkSettings"]["Networks"]
        assert config.get("PidMode", "") in ("", "private") and config.get("IpcMode") != "host"


def check_hardening():
    report = {}
    for service in (*SERVICES, *PROXIES):
        item = json.loads(subprocess.check_output(["docker", "inspect", cid(service)]))[0]
        check_container_config(item, cid(PROXIES[service]) if service in PROXIES else None)
        # PID 1 of the container, read from the host (proxy images ship no shell tools).
        status = Path(f"/proc/{item['State']['Pid']}/status").read_text()
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
        "uri": "https://catalog:8181/catalog",
        "ssl": {"cabundle": CA_FILE},
        "warehouse": "qualification",
        "s3.endpoint": "https://s3:8333",
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
    for key in (
        "admin",
        "postgres",
        "encryption",
        "access",
        "secret",
        "wrong",
        "sail_access",
        "sail_secret",
        "trino_shared",
        "truststore",
    )
}
LAKEKEEPER_PG = "postgresql://lakekeeper:{}@postgres:5432/lakekeeper?sslmode=verify-full&sslrootcert=/run/tls/ca.crt"


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
                    },
                    {
                        # Sail's own static key: SeaweedFS records which identity
                        # signed Sail's requests now that the wire is encrypted (T10).
                        "name": "sail",
                        "credentials": [
                            {"accessKey": CREDS["sail_access"], "secretKey": CREDS["sail_secret"]}
                        ],
                        "actions": ["Read:warehouse", "Write:warehouse", "List:warehouse"],
                    },
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
    # Loopback-only backend and metrics; clients reach it through the TLS proxy.
    (RUNTIME / "lakekeeper.env").write_text(
        "LAKEKEEPER__BIND_IP=127.0.0.1\n"
        "LAKEKEEPER__LISTEN_PORT=8182\n"
        "LAKEKEEPER__METRICS_PORT=9000\n"
        "LAKEKEEPER__BASE_URI=https://catalog:8181\n"
        f"LAKEKEEPER__PG_DATABASE_URL_WRITE={LAKEKEEPER_PG.format(CREDS['postgres'])}\n"
        f"LAKEKEEPER__PG_ENCRYPTION_KEY={CREDS['encryption']}\n"
        "SSL_CERT_FILE=/run/tls/ca.crt\n"
    )
    (RUNTIME / "trino.env").write_text(
        f"S3_ACCESS_KEY_ID={CREDS['access']}\nS3_SECRET_ACCESS_KEY={CREDS['secret']}\n"
    )
    (RUNTIME / "sail.env").write_text(
        f"AWS_ACCESS_KEY_ID={CREDS['sail_access']}\nAWS_SECRET_ACCESS_KEY={CREDS['sail_secret']}\n"
    )
    for name in ("lakekeeper.env", "trino.env", "sail.env"):
        (RUNTIME / name).chmod(0o600)
    shutil.copytree(ROOT / "integration/trino", RUNTIME / "trino")
    with (RUNTIME / "trino/config.properties").open("a") as config:
        config.write(f"internal-communication.shared-secret={CREDS['trino_shared']}\n")
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

    # Destructive-maintenance fixture ONLY. Main and encoding-canary catalogs retain
    # Trino's default seven-day minimums; T11 asserts both default refusals.
    (RUNTIME / "trino/catalog/maintenance.properties").write_text(
        content
        + "\n# TEST ONLY: disposable T11 table; never use these values in production.\n"
        + "iceberg.expire-snapshots.min-retention=0s\n"
        + "iceberg.remove-orphan-files.min-retention=0s\n"
    )

    # The pinned image requires read-only, non-world-readable configuration.
    subprocess.run(["sudo", "chown", "-R", "0:0", str(RUNTIME / "trino")], check=True)
    for path in [RUNTIME / "trino", *(RUNTIME / "trino").rglob("*")]:
        mode = "0750" if path.is_dir() else "0440"
        subprocess.run(["sudo", "chmod", mode, str(path)], check=True)
    from tls_setup import prepare as tls_prepare

    record("TLS_certificates", tls_prepare(CREDS["truststore"]))


def pg_tls_ready():
    """SSLRequest then a fully verified handshake to postgres:5432 (no credentials)."""
    with socket.create_connection(("postgres", 5432), timeout=5) as raw:
        raw.sendall(struct.pack("!ii", 8, 80877103))
        assert raw.recv(1) == b"S", "PostgreSQL refused TLS negotiation"
        with tls_context().wrap_socket(raw, server_hostname="postgres") as secure:
            return secure.version() in ("TLSv1.2", "TLSv1.3")


def catalog_ready():
    backend = subprocess.run(
        DC + ["exec", "-T", "catalog", "lakekeeper", "healthcheck", "-s"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return backend.returncode == 0 and http("GET", "https://catalog:8181/health")[0] == 200


def trino_ready():
    return http("GET", "https://trino:8443/v1/info")[1].get("starting") is False


def provision(commands):
    """Run the SeaweedFS shell with the provisioner's own mTLS client identity."""
    name = "lakehouse-integration-provisioner"
    try:
        result = subprocess.run(
            DC
            + ["run", "--name", name, "--no-deps", "-T", "provisioner", "shell"]
            + ["-master=master:9333", "-filer=filer:8888"],
            input=commands,
            text=True,
            capture_output=True,
            timeout=120,
        )
        check_container_config(json.loads(subprocess.check_output(["docker", "inspect", name]))[0])
        return result
    finally:
        subprocess.run(["docker", "rm", "-f", name], check=True, stdout=subprocess.DEVNULL)


def start():
    compose("up", "-d", "postgres", "master", "volume", "filer", "s3")
    hosts()
    wait("PostgreSQL verified TLS", pg_tls_ready)
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
    compose("up", "-d", "catalog", "catalog-proxy")
    hosts()
    wait("Lakekeeper behind its TLS proxy", catalog_ready)

    # The hardened gateway disables auto-create. Register the bucket before Lakekeeper validates it.
    def bucket():
        result = provision("s3.bucket.create -name warehouse\ns3.bucket.list\n")
        return "warehouse" in result.stdout

    wait("registered bucket", bucket)
    status, _ = http(
        "POST", "https://catalog:8181/management/v1/bootstrap", {"accept-terms-of-use": True}
    )
    assert status == 204, status
    profile = {
        "type": "s3",
        "bucket": "warehouse",
        "region": "local",
        "sts-enabled": False,
        "flavor": "s3-compat",
        "endpoint": "https://s3:8333",
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
    status, body = http("POST", "https://catalog:8181/management/v1/warehouse", bad)
    assert status == 400 and "signature" in json.dumps(body).lower(), (status, body)
    record("wrong_s3_secret", {"status": status, "body": body})
    status, body = http("POST", "https://catalog:8181/management/v1/warehouse", warehouse)
    assert status in (200, 201), (status, body)
    record("warehouse", {"profile": profile, "response": body})
    compose("up", "-d", "trino", "sail", "sail-proxy")
    hosts()
    wait("Trino over HTTPS", trino_ready, 180)
    from sail_probe import ready

    ready(sys.modules[__name__])
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
    old = {service: cid(service) for service in (*SERVICES, *PROXIES)}
    # Down removes every container and network, retaining only named volumes and secrets.
    logs = subprocess.run(DC + ["logs", "--no-color"], text=True, capture_output=True, check=True)
    (REPORTS / "services-before-recreation.log").write_text(logs.stdout + logs.stderr)
    compose("down", "--timeout", "30")
    compose("up", "-d")
    hosts()
    wait("catalog and proxy after restart", catalog_ready)
    wait("Trino after restart", trino_ready, 180)
    from sail_probe import ready

    ready(sys.modules[__name__])
    new = {service: cid(service) for service in old}
    assert all(
        previous and new[service] and new[service] != previous for service, previous in old.items()
    )
    record("container_recreation", {"before": old, "after": new})
    from tls_checks import exposure

    # Recreated proxies must not strand on an old namespace or expose plaintext.
    probe("TLS_exposure_after_recreation", lambda: exposure(sys.modules[__name__]))
    probe("T9_remote_signing_restart", REMOTE.after)
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
    from sail_probe import verify_restart as sail_restart

    sail_result = sail_restart(sys.modules[__name__])
    from maintenance import read as maintenance_read

    result = {
        "maintenance": maintenance_read(sys.modules[__name__]),
        "sail": sail_result,
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
        endpoint_url="https://s3:8333",
        verify=CA_FILE,
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
    for name in ("from_trino", "from_python", "encoding_canary", "from_sail"):
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
    assert rows == ["encoding_canary", "from_python", "from_sail", "from_trino"], rows
    return {"objects": len(objects), "tables": evidence, "postgres_catalog_rows": rows}


def secret_isolation():
    item = json.loads(subprocess.check_output(["docker", "inspect", cid("s3")]))[0]
    mounts = {m["Destination"]: m for m in item["Mounts"] if m["Type"] == "bind"}
    assert set(mounts) == {"/run/secrets", "/etc/seaweedfs"}, mounts
    assert not any(m["RW"] for m in mounts.values())
    assert Path(mounts["/run/secrets"]["Source"]).resolve() == (RUNTIME / "s3").resolve()
    listing = subprocess.check_output(
        DC + ["exec", "-T", "s3", "ls", "-A", "/run/secrets"], text=True
    )
    assert listing.splitlines() == ["s3.json"], listing
    from tls_checks import key_isolation

    tls = key_isolation(sys.modules[__name__])
    for name in ("postgres-password", "lakekeeper-password"):
        result = subprocess.run(
            DC + ["exec", "-T", "s3", "cat", "/run/secrets/" + name], capture_output=True
        )
        assert result.returncode != 0 and b"No such file" in result.stderr, result.stderr
    # An environment leak is as serious as a mount leak.
    for service in ("master", "volume", "filer", "s3", "trino", "sail", *PROXIES):
        config = json.loads(subprocess.check_output(["docker", "inspect", cid(service)]))[0][
            "Config"
        ]
        assert all(value not in json.dumps(config) for value in (CREDS["admin"], CREDS["postgres"]))
    for proxy in PROXIES:
        config = json.dumps(
            json.loads(subprocess.check_output(["docker", "inspect", cid(proxy)]))[0]["Config"]
        )
        assert not any(value in config for value in CREDS.values()), proxy
    from sail_probe import secret_isolation as sail_isolation

    return {
        "s3": "S3 sees only s3.json; PostgreSQL passwords are absent and unreadable",
        "tls": tls,
        "sail": sail_isolation(sys.modules[__name__]),
    }


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
            {"LAKEKEEPER__PG_DATABASE_URL_WRITE": LAKEKEEPER_PG.format(CREDS["wrong"])},
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
    global CREDS, REMOTE
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
        from sail_probe import interoperability

        probe("T10_sail", lambda: interoperability(sys.modules[__name__]))
        probe("T4_location", location)
        from maintenance import exercise as maintenance_exercise

        probe("T11_maintenance", lambda: maintenance_exercise(sys.modules[__name__]))
        from evolution import exercise as evolution_exercise

        probe("T12_evolution", lambda: evolution_exercise(sys.modules[__name__]))
        probe("T6_negative", negatives)
        probe("T7_secret_isolation", secret_isolation)
        import tls_checks

        probe("TLS_exposure", lambda: tls_checks.exposure(sys.modules[__name__]))
        probe("TLS_seaweedfs_canaries", lambda: tls_checks.seaweed_canaries(sys.modules[__name__]))
        probe("TLS_certificate_negatives", lambda: tls_checks.negatives(sys.modules[__name__]))
        from remote_signing import RestartDiagnostic

        REMOTE = RestartDiagnostic(rest_catalog, REPORTS, CREDS)
        probe("T9_remote_signing_before", REMOTE.start)
        probe("T5_persistence", restart)
        from crash import crash_durability

        probe("T8_crash_durability", lambda: crash_durability(sys.modules[__name__]))
        probe("TLS_exposure_after_crash", lambda: tls_checks.exposure(sys.modules[__name__]))
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
        "T8_crash_durability",
        "encoding_canary",
        "T10_sail",
        "T11_maintenance",
        "T12_evolution",
        "T9_remote_signing_before",
        "T9_remote_signing_restart",
        "TLS_exposure",
        "TLS_exposure_after_recreation",
        "TLS_seaweedfs_canaries",
        "TLS_certificate_negatives",
        "TLS_exposure_after_crash",
    }
    assert expected <= RESULTS.keys(), "Missing tests: " + str(expected - RESULTS.keys())
    assert not any(isinstance(v, dict) and v.get("status") == "fail" for v in RESULTS.values()), (
        "See reports/results.json"
    )


if __name__ == "__main__":
    main()
