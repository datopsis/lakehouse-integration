"""Unmodified pinned query engines; no grant or TLS implementation substituted."""

import json
import os
import shutil
import subprocess

import requests
from catalog import LABEL, ROWS, stop
from common import NETWORK, ROOT, WORK, host, run, secret, wait, write


def ready_or_error(name, ready, seconds=180):
    def running():
        return json.loads(run("docker", "inspect", name))[0]["State"]["Running"]

    # Surface an exited engine's actual error, not a misleading readiness timeout.
    wait(lambda: not running() or ready(), seconds)
    if not running():
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        raise AssertionError({"container": name, "startup_error": logs.stdout + logs.stderr})


def trino(catalog, mode="credential"):
    provider = catalog.provider
    directory = WORK / ("trino-" + provider.name + "-" + mode)
    shutil.copytree(ROOT / "integration/trino", directory)
    config = (directory / "catalog/iceberg.properties").read_text()
    config = config.replace("http://catalog:8181/catalog", catalog.base + "/catalog")
    config = config.replace("warehouse=qualification", "warehouse=" + catalog.warehouse)
    config = config.replace("security=NONE", "security=OAUTH2")
    config = config.replace("http://s3:8333", catalog.storage.endpoint)
    config += (
        "\niceberg.rest-catalog.oauth2.server-uri=" + provider.discovery["token_endpoint"] + "\n"
    )
    config += "iceberg.rest-catalog.oauth2.scope=openid profile\n"
    env = {
        "TRINO_UBI_ALLOW_INSECURE": "true",
        "S3_ACCESS_KEY_ID": catalog.storage.access,
        "S3_SECRET_ACCESS_KEY": catalog.storage.password,
    }
    if mode == "credential":
        config += "iceberg.rest-catalog.oauth2.credential=lakekeeper:${ENV:IDP_CLIENT_SECRET}\n"
        env["IDP_CLIENT_SECRET"] = provider.client_secret
    else:
        config += "iceberg.rest-catalog.oauth2.token=${ENV:IDP_TOKEN}\n"
        config += "iceberg.rest-catalog.oauth2.token-exchange-enabled=true\n"
        env["IDP_TOKEN"] = provider.service_token if mode == "exchange" else provider.machine_token
    write(directory / "catalog/iceberg.properties", config)
    trust_password = secret()
    run(
        "keytool",
        "-importcert",
        "-noprompt",
        "-alias",
        "bakeoff",
        "-file",
        provider.ca,
        "-keystore",
        directory / "truststore.jks",
        "-storetype",
        "JKS",
        "-storepass",
        trust_password,
    )
    # JSSE discovers this public-certificate JKS without forbidden JVM overrides.
    # JKS certificates load with a null password; the read-only mount protects integrity.
    for path in directory.rglob("*"):
        path.chmod(0o755 if path.is_dir() else 0o644)
    # Truststore contains only the public CA; credentials remain in a runner-only env file.
    envfile = directory.parent / (directory.name + ".env")
    write(envfile, "".join(f"{key}={value}\n" for key, value in env.items()))
    name = "idp-" + directory.name
    run(
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--label",
        LABEL,
        "--network",
        NETWORK,
        "--memory=3g",
        "--cpus=2",
        "--env-file",
        envfile,
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "-v",
        f"{directory}:/etc/trino:ro",
        "-v",
        f"{directory / 'truststore.jks'}:/opt/java/lib/security/jssecacerts:ro",
        "--tmpfs",
        "/var/lib/trino:rw,noexec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=512m",
        "--tmpfs",
        "/tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=256m",
        "localhost/trino-ubi:integration",
    )
    try:
        address = host(name, name + ".idp.test")
        base = "http://" + address + ":8080"
        session = requests.Session()
        session.trust_env = False
        ready_or_error(
            name, lambda: session.get(base + "/v1/info", timeout=5).json().get("starting") is False
        )

        def sql(statement):
            response = session.post(
                base + "/v1/statement",
                data=statement,
                headers={"X-Trino-User": "bakeoff"},
                timeout=30,
            )
            response.raise_for_status()
            page = response.json()
            rows = []
            while True:
                assert "error" not in page, page.get("error")
                rows.extend(page.get("data", []))
                if "nextUri" not in page:
                    return rows
                response = session.get(page["nextUri"], timeout=120)
                response.raise_for_status()
                page = response.json()

        tables = sql("SHOW TABLES FROM iceberg.bakeoff")
        assert tables == [["sample"]], tables
        rows = sql("SELECT id, label FROM iceberg.bakeoff.sample ORDER BY id")
        assert rows == [[r["id"], r["label"]] for r in ROWS], rows
        return {
            "tables": tables,
            "rows": rows,
            "mode": mode,
            "catalog_uri": catalog.base,
            "oauth_server_uri": provider.discovery["token_endpoint"],
            "tls_trust": "per-run CA in JVM truststore; verification enabled",
        }
    finally:
        stop(name)


def sail(catalog, external_token=False):
    provider = catalog.provider
    name = "idp-sail-" + provider.name + ("-token" if external_token else "-grant")
    directory = WORK / name
    directory.mkdir()
    # These are the actual 0.7.3 config fields. It has no client credential/server-uri fields.
    config = (
        f'[{{type="iceberg-rest", name="bakeoff", uri="{catalog.base}/catalog", '
        f'warehouse="{catalog.warehouse}"'
    )
    if external_token:
        write(directory / "token", provider.machine_token)
        run("sudo", "chown", "10001:10001", directory / "token")
        config += ', bearer_access_token_file="/run/catalog-token"'
    config += "}]"
    env = {
        "SAIL_CATALOG__LIST": config,
        "SSL_CERT_FILE": "/ca/ca.pem",
        "AWS_ACCESS_KEY_ID": catalog.storage.access,
        "AWS_SECRET_ACCESS_KEY": catalog.storage.password,
        "AWS_ENDPOINT": catalog.storage.endpoint,
        "AWS_REGION": "local",
        "AWS_ALLOW_HTTP": "true",
        "AWS_VIRTUAL_HOSTED_STYLE_REQUEST": "false",
    }
    envfile = directory / "env"
    write(envfile, "".join(f"{key}={value}\n" for key, value in env.items()))
    args = [
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--label",
        LABEL,
        "--network",
        NETWORK,
        "--memory=2g",
        "--cpus=2",
        "--env-file",
        envfile,
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        "-v",
        f"{provider.ca}:/ca/ca.pem:ro",
        "-v",
        f"{ROOT / 'integration/sail/config.json'}:/etc/sail/config.json:ro",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=10001,gid=10001",
        "--tmpfs",
        "/var/lib/sail:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=10001,gid=10001",
    ]
    if external_token:
        args += ["-v", f"{directory / 'token'}:/run/catalog-token:ro"]
    run(*args, "localhost/sail-ubi:integration")
    try:
        address = host(name, name + ".idp.test")
        ready_or_error(
            name,
            lambda: (
                subprocess.run(
                    [
                        "docker",
                        "exec",
                        name,
                        "/usr/bin/python3.12",
                        "-I",
                        "-B",
                        "/opt/sail/healthcheck.py",
                    ],
                    capture_output=True,
                ).returncode
                == 0
            ),
        )
        result = subprocess.run(
            [
                str(ROOT / ".sources/sail-venv/bin/python"),
                str(ROOT / "evaluation/idp/sail_read.py"),
            ],
            env=dict(os.environ, SAIL_TEST_URL=f"sc://{address}:50051"),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, {
            "mode": "external-token-file" if external_token else "no-native-grant-provider",
            "stdout": result.stdout,
            "stderr": result.stderr,
            "source_limitation": "Sail 0.7.3 has static/file bearer providers, no client-credentials grant",
        }
        evidence = json.loads(
            next(
                line.removeprefix("SAIL_RESULT=")
                for line in result.stdout.splitlines()
                if line.startswith("SAIL_RESULT=")
            )
        )
        assert external_token, "Sail unexpectedly read without a token; investigate auth bypass"
        return {
            **evidence,
            "external_token_lifecycle": True,
            "native_client_credentials": False,
            "tls_trust": "SSL_CERT_FILE per-run CA",
        }
    finally:
        stop(name)
