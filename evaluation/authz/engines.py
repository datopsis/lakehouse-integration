"""Trino native client credentials over verified TLS, with a fixed machine identity."""

import json
import shutil

from catalog import ROWS
from clients import ready_or_error
from common import HTTPS, ROOT, WORK, run, secret, write
from fixture import container, leaf, transport


def trino_denial(statement, error):
    """Only the measured hidden namespace or a real ForbiddenException qualifies."""
    if statement == "SELECT * FROM iceberg.denied.sample":
        assert error["errorName"] == "SCHEMA_NOT_FOUND", error
        assert error["errorCode"] == 45 and error["errorType"] == "USER_ERROR", error
        assert error["message"] == "line 1:15: Schema 'denied' does not exist", error
    else:
        assert error["errorName"] in (
            "ICEBERG_CATALOG_ERROR",
            "ICEBERG_COMMIT_ERROR",
            "PERMISSION_DENIED",
        ), error
        assert "org.apache.iceberg.exceptions.ForbiddenException" in json.dumps(error), error
    return error


def trino(catalog):
    provider = catalog.provider
    directory = WORK / "trino-authz"
    shutil.copytree(ROOT / "integration/trino", directory)
    tls = leaf("trino")
    pem = directory / "server.pem"
    # Key is never in artifact output; read with sudo after leaf permissions are set.
    write(pem, (tls / "cert.pem").read_text() + run("sudo", "cat", tls / "key.pem"))
    run("sudo", "chown", "10001:0", pem)
    run("sudo", "chmod", "0400", pem)
    with (directory / "node.properties").open("a") as output:
        output.write("\nnode.internal-address=trino\n")
    config = (directory / "catalog/iceberg.properties").read_text()
    config = config.replace("http://catalog:8181/catalog", catalog.base + "/catalog")
    config = config.replace("warehouse=qualification", "warehouse=bakeoff").replace(
        "security=NONE", "security=OAUTH2"
    )
    config = config.replace("http://s3:8333", catalog.storage.endpoint)
    config += (
        "\niceberg.rest-catalog.oauth2.server-uri=" + provider.discovery["token_endpoint"] + "\n"
    )
    config += "iceberg.rest-catalog.oauth2.credential=lakekeeper:${ENV:IDP_CLIENT_SECRET}\n"
    config += "iceberg.rest-catalog.oauth2.scope=openid profile\n"
    write(directory / "catalog/iceberg.properties", config)
    write(
        directory / "config.properties",
        "coordinator=true\nnode-scheduler.include-coordinator=true\n"
        "http-server.http.enabled=false\nhttp-server.https.enabled=true\nhttp-server.https.port=8443\n"
        "http-server.https.keystore.path=/etc/trino/server.pem\ndiscovery.uri=https://trino:8443\n"
        "internal-communication.https.required=true\n"
        "internal-communication.https.keystore.path=/etc/trino/server.pem\n"
        "internal-communication.https.truststore.path=/ca/ca.pem\n"
        f"internal-communication.shared-secret={secret()}\n"
        "query.max-memory=256MB\nquery.max-memory-per-node=256MB\nmemory.heap-headroom-per-node=256MB\n"
        "http-server.log.enabled=false\n",
    )
    run(
        "keytool",
        "-importcert",
        "-noprompt",
        "-alias",
        "evaluation",
        "-file",
        provider.ca,
        "-keystore",
        directory / "truststore.jks",
        "-storetype",
        "JKS",
        "-storepass",
        secret(),
    )
    for path in directory.rglob("*"):
        if path != pem:
            path.chmod(0o755 if path.is_dir() else 0o644)
    run("sudo", "chown", "10001:0", directory / "config.properties")
    run("sudo", "chmod", "0400", directory / "config.properties")
    env = {
        "TRINO_UBI_ALLOW_INSECURE": "true",
        "S3_ACCESS_KEY_ID": catalog.storage.access,
        "S3_SECRET_ACCESS_KEY": catalog.storage.password,
        "IDP_CLIENT_SECRET": provider.client_secret,
    }
    container(
        "trino",
        "localhost/trino-ubi:integration",
        env=env,
        mounts=[
            (directory, "/etc/trino"),
            (directory / "truststore.jks", "/opt/java/lib/security/jssecacerts"),
            (provider.ca, "/ca/ca.pem"),
        ],
        extra=[
            "--memory=3g",
            "--cpus=2",
            "--tmpfs",
            "/var/lib/trino:uid=10001,gid=0,size=512m",
            "--tmpfs",
            "/tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,size=256m",
        ],
    )
    http = HTTPS(provider.ca)
    ready_or_error(
        "trino",
        lambda: http.json("GET", "https://trino:8443/v1/info").get("starting") is False,
        180,
    )
    tls_evidence = transport("trino", 8443, provider.ca)

    def sql(statement):
        page = http.json(
            "POST",
            "https://trino:8443/v1/statement",
            data=statement,
            headers={"X-Trino-User": "evaluation"},
        )
        rows = []
        while True:
            if "error" in page:
                return {"error": page["error"]}
            rows.extend(page.get("data", []))
            if "nextUri" not in page:
                return {"rows": rows}
            page = http.json("GET", page["nextUri"])

    listed = sql("SHOW TABLES FROM iceberg.bakeoff")
    assert listed == {"rows": [["sample"]]}, listed
    selected = sql("SELECT * FROM iceberg.bakeoff.sample ORDER BY id")
    assert selected == {"rows": [[r["id"], r["label"]] for r in ROWS]}, selected
    negatives = {}
    for statement in (
        "SELECT * FROM iceberg.denied.sample",
        "INSERT INTO iceberg.bakeoff.sample VALUES (3, 'forbidden')",
        "UPDATE iceberg.bakeoff.sample SET label='forbidden' WHERE id=1",
        "DELETE FROM iceberg.bakeoff.sample WHERE id=1",
        "CREATE TABLE iceberg.bakeoff.forbidden (id BIGINT)",
        "DROP TABLE iceberg.bakeoff.sample",
    ):
        result = sql(statement)
        assert "error" in result, result
        negatives[statement] = trino_denial(statement, result["error"])
    return {"tls": tls_evidence, "rows": ROWS, "denials": negatives}


def sail(catalog):
    """External token file; verified Spark Connect TLS via the unchanged owner profile."""
    import json
    import os
    import subprocess

    from catalog import PROXY_IMAGE
    from common import WORK

    provider = catalog.provider
    directory = WORK / "sail-authz"
    directory.mkdir()
    tls = leaf("sail")
    run("sudo", "cp", tls / "cert.pem", tls / "server.crt")
    run("sudo", "cp", tls / "key.pem", tls / "server.key")
    profile = ROOT / ".sources/nginx-ubi/examples/profiles/sail"
    container(
        "sail",
        PROXY_IMAGE,
        ["-c", "/etc/nginx/profile/nginx.conf", "-g", "daemon off;"],
        mounts=[(tls, "/etc/nginx/tls"), (profile, "/etc/nginx/profile")],
        extra=[
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs",
            "/tmp:mode=1777,size=64m",
        ],
    )
    token = directory / "token"
    write(token, provider.token())
    run("sudo", "chown", "10001:10001", token)
    config = directory / "config.json"
    write(config, {"bind": "127.0.0.1", "port": 50052, "allow_unauthenticated_remote": True})
    config.chmod(0o644)
    env = {
        "SAIL_CATALOG__LIST": f'[{{type="iceberg-rest", name="bakeoff", uri="{catalog.base}/catalog", warehouse="bakeoff", bearer_access_token_file="/run/catalog-token"}}]',
        "SSL_CERT_FILE": "/ca/ca.pem",
        "AWS_ACCESS_KEY_ID": catalog.storage.access,
        "AWS_SECRET_ACCESS_KEY": catalog.storage.password,
        "AWS_ENDPOINT": catalog.storage.endpoint,
        "AWS_REGION": "local",
        "AWS_ALLOW_HTTP": "false",
        "AWS_VIRTUAL_HOSTED_STYLE_REQUEST": "false",
    }
    container(
        "sail-backend",
        "localhost/sail-ubi:integration",
        env=env,
        mounts=[
            (provider.ca, "/ca/ca.pem"),
            (config, "/etc/sail/config.json"),
            (token, "/run/catalog-token"),
        ],
        network="container:sail",
        extra=[
            "--memory=2g",
            "--cpus=2",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs",
            "/tmp:uid=10001,gid=10001,size=256m",
            "--tmpfs",
            "/var/lib/sail:uid=10001,gid=10001,size=256m",
        ],
    )
    from common import wait

    wait(lambda: transport("sail", 50051, provider.ca), 120)
    wait(
        lambda: (
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "sail-backend",
                    "/usr/bin/python3.12",
                    "-c",
                    "import socket; socket.create_connection(('127.0.0.1', 50052), timeout=2).close()",
                ],
                capture_output=True,
            ).returncode
            == 0
        ),
        120,
    )
    result = subprocess.run(
        [
            str(ROOT / ".sources/sail-venv/bin/python"),
            str(ROOT / "evaluation/authz/sail_client.py"),
        ],
        env=dict(os.environ, GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(provider.ca)),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(
        next(
            line.removeprefix("SAIL_RESULT=")
            for line in result.stdout.splitlines()
            if line.startswith("SAIL_RESULT=")
        )
    )
    return {"tls": transport("sail", 50051, provider.ca), "token": "external file", **evidence}
