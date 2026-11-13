"""Native, TLS-only evaluation. Blocked cases remain explicit and fail qualification."""

import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time

import requests
from common import NETWORK, OUT, ROOT, WORK, decode, host, pki, run, save, secret, wait, write
from providers import Provider

RESULTS = {}
REQUIRED = (
    "trino_client_credentials_list_read",
    "pyiceberg_client_credentials_list_read",
    "sail_client_credentials_list_read",
    "human_pkce_lakekeeper",
    "valid_token",
    "wrong_audience",
    "expired_token",
    "different_key",
    "alg_none",
    "rotation_lakekeeper",
)


def test(name, fn):
    start = time.monotonic()
    try:
        value = fn()
        result = {"status": "pass", "value": value}
    except Exception as exc:
        result = {"status": "fail", "error_type": type(exc).__name__, "error": str(exc)}
    result["seconds"] = round(time.monotonic() - start, 3)
    RESULTS[name] = result
    save("results.json", RESULTS)
    print(name + ": " + result["status"], flush=True)
    return result


def build():
    sys.path.insert(0, str(ROOT / "integration"))
    import build as owner

    arch = owner.native_architecture()
    builds = {}
    # Same owner scripts, lock checks and binary/provenance assertions as Integration.
    # No need to build query engines while the token-transport prerequisite is blocked.
    for repo in ("postgresql-lakekeeper-ubi", "lakekeeper-ubi"):
        result = owner.build(repo, owner.PINS[repo], arch)
        builds[repo] = result
        save("builds.json", builds)
        assert result["status"] == "pass", result


def postgres():
    directory = WORK / "postgres"
    directory.mkdir()
    admin, password, encryption = secret(), secret(), secret()
    write(directory / "postgres-password", admin)
    write(directory / "lakekeeper-password", password)
    run("sudo", "chown", "-R", "root:root", directory)
    run("sudo", "chmod", "0440", directory / "postgres-password", directory / "lakekeeper-password")
    run(
        "docker",
        "run",
        "-d",
        "--name",
        "idp-postgres",
        "--network",
        NETWORK,
        "--network-alias",
        "postgres",
        "--label",
        "datopsis.idp-bakeoff=true",
        "-e",
        "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password",
        "-e",
        "POSTGRES_DB=lakekeeper",
        "-v",
        f"{directory}:/run/secrets:ro",
        "localhost/postgresql-lakekeeper-ubi:integration",
    )
    wait(
        lambda: (
            subprocess.run(
                ["docker", "exec", "idp-postgres", "pg_isready", "-h", "127.0.0.1"],
                capture_output=True,
            ).returncode
            == 0
        )
    )
    run(
        "docker",
        "exec",
        "-i",
        "idp-postgres",
        "psql",
        "-X",
        "-h",
        "/tmp",
        "-U",
        "postgres",
        "-d",
        "lakekeeper",
        input=(ROOT / "integration/postgres-init.sql").read_text(),
    )
    env = WORK / "lakekeeper.env"
    write(
        env,
        f"LAKEKEEPER__PG_DATABASE_URL_WRITE=postgres://lakekeeper:{password}@postgres:5432/lakekeeper\n"
        f"LAKEKEEPER__PG_ENCRYPTION_KEY={encryption}\n",
    )
    run(
        "docker",
        "run",
        "--rm",
        "--network",
        NETWORK,
        "--label",
        "datopsis.idp-bakeoff=true",
        "--env-file",
        env,
        "localhost/lakekeeper-ubi:integration",
        "migrate",
    )
    return env


def lakekeeper(provider, env):
    name = "idp-lakekeeper-" + provider.name
    run(
        "docker",
        "run",
        "-d",
        "--name",
        name,
        "--network",
        NETWORK,
        "--label",
        "datopsis.idp-bakeoff=true",
        "--env-file",
        env,
        "-e",
        "LAKEKEEPER__OPENID_PROVIDER_URI=" + provider.issuer,
        "-e",
        "LAKEKEEPER__OPENID_AUDIENCE=lakekeeper",
        "-e",
        "LAKEKEEPER__OPENID_SUBJECT_CLAIM=sub",
        "-e",
        "LAKEKEEPER__OPENID_ROLES_CLAIM=groups",
        "-e",
        "SSL_CERT_FILE=/ca/ca.pem",
        "-v",
        f"{WORK / 'ca/ca.pem'}:/ca/ca.pem:ro",
        "localhost/lakekeeper-ubi:integration",
        "serve",
    )
    address = host(name, "lakekeeper-" + provider.hostname)
    try:
        wait(
            lambda: (
                subprocess.run(
                    ["docker", "exec", name, "lakekeeper", "healthcheck", "-s"], capture_output=True
                ).returncode
                == 0
            )
        )
        # Anonymous negative only. NEVER attach an Authorization header to HTTP.
        anonymous = requests.Session()
        anonymous.trust_env = False
        response = anonymous.get(
            f"http://{address}:8181/catalog/v1/config", timeout=10, allow_redirects=False
        )
        assert response.status_code == 401, (response.status_code, response.text)
        context = ssl.create_default_context(cafile=str(provider.ca))
        try:
            with socket.create_connection((address, 8181), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname="lakekeeper-" + provider.hostname):
                    pass
        except ssl.SSLError as exc:
            return {
                "status": "blocked",
                "anonymous_http_status": response.status_code,
                "tls_error": str(exc),
                "reason": "Pinned Lakekeeper has no TLS listener; tokens never sent over HTTP.",
            }
        raise AssertionError(
            "Lakekeeper TLS unexpectedly available: implement full token/table assertions before qualification"
        )
    finally:
        log = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        save(name + ".log.json", {"log": log.stdout + log.stderr})
        run("docker", "rm", "-fv", name)


def machine(provider):
    r = provider.machine()
    if r.status_code != 200:
        raise AssertionError({"http_status": r.status_code, "response": r.text})
    token = r.json()
    secret(token["access_token"])
    header, claims = decode(token["access_token"])
    assert claims["iss"] == provider.issuer
    assert claims["aud"] == "lakekeeper" or "lakekeeper" in claims["aud"]
    assert claims["exp"] > time.time()
    assert header["kid"] in {
        key["kid"] for key in provider.http.json("GET", provider.discovery["jwks_uri"])["keys"]
    }
    provider.machine_token = token["access_token"]
    return {"header": header, "claims": claims, "token_type": token["token_type"]}


def human(provider):
    tokens = provider.human()
    header, claims = decode(tokens["access_token"])
    assert claims["iss"] == provider.issuer and claims["exp"] > time.time()
    provider.human_claims = claims
    provider.id_claims = decode(tokens["id_token"])[1]
    return {
        "access_token_header": header,
        "access_token_claims": claims,
        "id_token_claims": provider.id_claims,
        "flow": "authorization_code + S256 + state + nonce",
    }


def groups(provider):
    claims = provider.human_claims
    assert "lake-readers" in json.dumps(claims.get("groups", [])), claims
    return {
        "access_token_groups": claims["groups"],
        "id_token_groups": provider.id_claims.get("groups"),
    }


def exchange(provider):
    token = provider.exchange()
    secret(token["access_token"])
    header, claims = decode(token["access_token"])
    assert claims["aud"] == "lakekeeper" and claims["iss"] == provider.issuer
    provider.machine_token = token["access_token"]
    return {
        "header": header,
        "claims": claims,
        "custom_harness_request": True,
        "stock_client_compatibility": "NOT established by this direct RFC8693 request",
    }


def rotation(provider):
    old = decode(provider.machine_token)[0]["kid"]
    before = provider.http.json("GET", provider.discovery["jwks_uri"])
    provider.rotate()
    token = provider.exchange() if provider.name == "kanidm" else provider.machine().json()
    secret(token["access_token"])
    new = decode(token["access_token"])[0]["kid"]
    after = provider.http.json("GET", provider.discovery["jwks_uri"])
    assert new != old and new in {key["kid"] for key in after["keys"]}, (old, new, after)
    assert new not in {key["kid"] for key in before["keys"]}, before
    return {
        "old_kid": old,
        "new_kid": new,
        "before": before,
        "after": after,
        "scope": "IdP publishes new key and signs a new token; Lakekeeper cache refresh NOT tested",
    }


def operations(provider):
    # Five quiet process-RSS samples; include all PIDs in this container, exclude page cache.
    samples = []
    for _ in range(5):
        pids = run("docker", "top", provider.container, "-eo", "pid").splitlines()[1:]
        total = 0
        for pid in pids:
            text = run("sudo", "cat", f"/proc/{pid.strip()}/status")
            total += int(
                next(line.split()[1] for line in text.splitlines() if line.startswith("VmRSS:"))
            )
        samples.append(total)
        time.sleep(1)
    size = int(run("sudo", "du", "-sb", provider.path / "data").split()[0])
    return {
        "startup_to_https_ready_seconds": provider.startup_seconds,
        "idle_rss_kib_samples": samples,
        "idle_rss_kib_median": sorted(samples)[2],
        "data_directory_bytes": size,
        "container_cpu_limit": 2,
        "container_memory_limit_bytes": 2147483648,
        "startup_definition": "docker start through first verified HTTPS readiness (pull excluded)",
        "data_definition": "apparent bytes after provisioning and auth tests; not production capacity",
    }


def main():
    assert __debug__
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    assert arch == os.environ["INTEGRATION_ARCH"]
    OUT.mkdir(parents=True, exist_ok=True)
    RESULTS["run"] = {
        "architecture": arch,
        "uname": platform.machine(),
        "url": os.environ["RUN_URL"],
    }
    ca = pki()
    run("docker", "network", "create", "--internal", NETWORK)
    env = postgres()
    for name in ("keycloak", "rauthy", "kanidm"):
        provider = Provider(name, ca)
        started = test(name + "/startup_provision_discovery", lambda: provider.start(arch))
        for case in REQUIRED:
            RESULTS[name + "/" + case] = {
                "status": "blocked",
                "reason": "Lakekeeper verified-TLS prerequisite not met; no token sent",
            }
        if started["status"] == "pass":
            test(name + "/machine_token_endpoint", lambda: machine(provider))
            if name == "kanidm":
                test(name + "/service_account_exchange", lambda: exchange(provider))
            test(name + "/human_pkce_idp", lambda: human(provider))
            test(name + "/groups_claim", lambda: groups(provider))
            test(name + "/rotation_idp", lambda: rotation(provider))
            test(name + "/operations", lambda: operations(provider))
            test(name + "/lakekeeper_transport", lambda: lakekeeper(provider, env))
        save("results.json", RESULTS)
    # A successful evidence collector is not a passed qualification. Blockers keep this red.
    assert all(
        RESULTS[n + "/" + case]["status"] == "pass"
        for n in ("keycloak", "rauthy", "kanidm")
        for case in REQUIRED
    ), "Incomplete qualification; see results.json"


if __name__ == "__main__":
    if sys.argv[1:] == ["build"]:
        build()
    else:
        main()
