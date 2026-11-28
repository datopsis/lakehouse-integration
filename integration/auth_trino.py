"""Rauthy JWT ingress, stock OPA plugin, verified TLS on every HTTP hop."""

import shutil

from clients import ready_or_error
from common import HTTPS, ROOT, WORK, run, secret, write
from fixture import BACKEND_NETWORK, container, leaf, transport


def start(catalog, key, tokens, mode="batch"):
    directory = WORK / ("trino-s2-" + mode)
    shutil.copytree(ROOT / "integration/trino", directory)
    tls = WORK / "trino/tls"
    if not (tls / "cert.pem").exists():
        tls = leaf("trino")
    write(
        directory / "server.pem",
        (tls / "cert.pem").read_text() + run("sudo", "cat", tls / "key.pem"),
    )
    password = secret()
    run(
        "keytool",
        "-importcert",
        "-noprompt",
        "-alias",
        "s2",
        "-file",
        catalog.provider.ca,
        "-keystore",
        directory / "trust.p12",
        "-storetype",
        "PKCS12",
        "-storepass",
        password,
    )
    write(directory / "trust-password", password)
    write(directory / "ca.pem", catalog.provider.ca.read_text())
    write(
        directory / "truststore.properties",
        "path=/etc/trino/trust.p12\ntype=PKCS12\npassword-file=/etc/trino/trust-password\n",
    )
    write(directory / "context.properties", "serviceKey=" + key + "\n")
    write(directory / "user-mapping.json", {"rules": [{"pattern": "(.*)", "user": "oidc~$1"}]})
    base = "https://cedar:8443/opa/"
    config = "access-control.name=opa\nopa.policy.uri=" + base + "allow\n"
    if mode == "batch":
        config += (
            "opa.policy.batched-uri="
            + base
            + "batch\nopa.policy.batch-column-masking-uri="
            + base
            + "batch_masks\n"
        )
    config += (
        "opa.policy.row-filters-uri="
        + base
        + "rows\nopa.policy.column-masking-uri="
        + base
        + "mask\n"
    )
    config += "opa.context-file=/etc/trino/context.properties\nopa.http-client.request-timeout=5s\n"
    write(directory / "access-control.properties", config)
    write(
        directory / "config.properties",
        "coordinator=true\nnode-scheduler.include-coordinator=true\n"
        "http-server.http.enabled=false\nhttp-server.https.enabled=true\nhttp-server.https.port=8443\n"
        "http-server.https.keystore.path=/etc/trino/server.pem\nhttp-server.authentication.type=JWT\n"
        "http-server.authentication.jwt.key-file=" + catalog.provider.discovery["jwks_uri"] + "\n"
        "http-server.authentication.jwt.required-issuer=" + catalog.provider.issuer + "\n"
        "http-server.authentication.jwt.required-audience=lakekeeper\n"
        "http-server.authentication.jwt.user-mapping.file=/etc/trino/user-mapping.json\n"
        "discovery.uri=https://trino:8443\ninternal-communication.https.required=true\n"
        "internal-communication.https.keystore.path=/etc/trino/server.pem\n"
        "internal-communication.https.truststore.path=/etc/trino/ca.pem\n"
        "internal-communication.shared-secret=" + secret() + "\n"
        "query.max-memory=256MB\nquery.max-memory-per-node=256MB\nmemory.heap-headroom-per-node=256MB\n"
        "http-server.log.enabled=false\n",
    )
    write(
        directory / "node.properties",
        "node.environment=s2\nnode.id=s2-"
        + mode
        + "\nnode.data-dir=/var/lib/trino\nnode.internal-address=trino\n",
    )
    path = directory / "catalog/iceberg.properties"
    config = path.read_text().replace("https://catalog:8181/catalog", catalog.base + "/catalog")
    config = config.replace("warehouse=qualification", "warehouse=bakeoff").replace(
        "security=NONE", "security=OAUTH2"
    )
    config += (
        "\niceberg.rest-catalog.oauth2.server-uri="
        + catalog.provider.discovery["token_endpoint"]
        + "\n"
    )
    config += "iceberg.rest-catalog.oauth2.credential=lakekeeper:${ENV:IDP_CLIENT_SECRET}\niceberg.rest-catalog.oauth2.scope=openid profile\n"
    write(path, config)
    for path in directory.rglob("*"):
        if path.is_file():
            run("sudo", "chown", "10001:0", path)
            run("sudo", "chmod", "0400", path)
        else:
            path.chmod(0o755)
    container(
        "trino",
        "localhost/trino-ubi:integration",
        env={
            "S3_ACCESS_KEY_ID": catalog.storage.access,
            "S3_SECRET_ACCESS_KEY": catalog.storage.password,
            "IDP_CLIENT_SECRET": catalog.provider.client_secret,
        },
        mounts=[(directory, "/etc/trino")],
        extra=[
            "--memory=3g",
            "--cpus=2",
            "--tmpfs",
            "/var/lib/trino:uid=10001,gid=0,size=512m",
            "--tmpfs",
            "/tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,size=256m",
        ],
    )
    run("docker", "network", "connect", BACKEND_NETWORK, "trino")
    http = HTTPS(catalog.provider.ca)
    ready_or_error(
        "trino",
        lambda: http.json("GET", "https://trino:8443/v1/info").get("starting") is False,
        180,
    )
    version = http.json("GET", "https://trino:8443/v1/info")["nodeVersion"]["version"]
    assert version == "484", version
    evidence = {
        "version": version,
        "mode": mode,
        "tls": transport("trino", 8443, catalog.provider.ca),
    }

    def sql(user, statement):
        headers = {"X-Trino-User": user, "Authorization": "Bearer " + tokens[user]}
        page = http.json("POST", "https://trino:8443/v1/statement", data=statement, headers=headers)
        rows = []
        while True:
            if "error" in page:
                # No earlier page may leak rows before a structured query failure.
                assert not rows and not page.get("data"), "Query leaked rows before failure"
                return {"error": page["error"]}
            rows.extend(page.get("data", []))
            if "nextUri" not in page:
                return {"rows": rows}
            page = http.json("GET", page["nextUri"], headers=headers)

    return sql, evidence
