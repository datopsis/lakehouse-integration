"""Trino native client credentials over verified TLS, with a fixed machine identity."""

import shutil

from catalog import ROWS
from clients import ready_or_error
from common import HTTPS, ROOT, WORK, run, secret, write
from fixture import container, leaf, transport


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
        ],
        extra=[
            "--memory=3g",
            "--cpus=2",
            "--tmpfs",
            "/var/lib/trino:uid=10001,gid=0,size=512m",
            "--tmpfs",
            "/tmp/trino:uid=10001,gid=0,size=256m",
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

    assert sql("SHOW TABLES FROM iceberg.bakeoff") == {"rows": [["sample"]]}
    assert sql("SELECT * FROM iceberg.bakeoff.sample ORDER BY id") == {
        "rows": [[r["id"], r["label"]] for r in ROWS]
    }
    negatives = {}
    for statement in (
        "SELECT * FROM iceberg.denied.sample",
        "INSERT INTO iceberg.bakeoff.sample VALUES (3, 'forbidden')",
    ):
        result = sql(statement)
        assert "error" in result, result
        error = result["error"]
        # Require actual catalog authorization failure, never syntax/network/authn failure.
        import json

        message = json.dumps(error)
        assert any(
            x in message
            for x in (
                "Forbidden",
                "forbidden",
                "not authorized",
                "NotAuthorized",
                "CannotSee",
                "does not exist",
            )
        ), error
        assert error["errorName"] in (
            "ICEBERG_CATALOG_ERROR",
            "TABLE_NOT_FOUND",
            "PERMISSION_DENIED",
        ), error
        negatives[statement] = error
    return {"tls": tls_evidence, "rows": ROWS, "denials": negatives}
