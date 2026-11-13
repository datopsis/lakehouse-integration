"""Native IdP and real catalog assertions through the approved loopback TLS proxy."""

import json
import os
import platform
import socket
import ssl
import subprocess
import sys
import time

import requests
from catalog import Catalog, Storage, bad_token, build_proxy, expired
from clients import sail, trino
from common import NETWORK, OUT, ROOT, WORK, decode, pki, run, save, secret, wait, write
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
        result = {
            "status": value.get("status", "pass") if isinstance(value, dict) else "pass",
            "value": value,
        }
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
    for repo in owner.PINS:
        result = owner.build(repo, owner.PINS[repo], arch)
        builds[repo] = result
        save("builds.json", builds)
        assert result["status"] == "pass", result
    builds["nginx-ubi"] = build_proxy(arch, owner)
    save("builds.json", builds)


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


def machine(provider):
    r = provider.machine()
    if r.status_code != 200:
        raise AssertionError({"http_status": r.status_code, "response": r.text})
    token = r.json()
    secret(token["access_token"])
    assert token["token_type"].lower() == "bearer"
    assert token["expires_in"] > 0
    provider.machine_token = token["access_token"]
    provider.client_credentials_token = provider.machine_token
    return {
        "http_status": r.status_code,
        "token_type": token["token_type"],
        "expires_in": token["expires_in"],
        "segments": len(token["access_token"].split(".")),
    }


def machine_claims(provider):
    segments = len(provider.machine_token.split("."))
    assert segments == 3, (
        f"Expected signed JWT (3 segments), received {segments}-segment token (JWE is not a Lakekeeper JWT)"
    )
    header, claims = decode(provider.machine_token)
    assert claims["iss"] == provider.issuer
    assert claims["aud"] == "lakekeeper" or claims["aud"] == ["lakekeeper"]
    assert claims["exp"] > time.time()
    assert isinstance(claims["sub"], str) and claims["sub"]
    assert header["kid"] in {
        key["kid"] for key in provider.http.json("GET", provider.discovery["jwks_uri"])["keys"]
    }
    return {"header": header, "claims": claims}


def pyiceberg_token(provider):
    from pyiceberg.catalog.rest.auth import LegacyOAuth2AuthManager

    session = requests.Session()
    session.verify = str(provider.ca)
    session.trust_env = False
    session.max_redirects = 0
    auth = LegacyOAuth2AuthManager(
        session=session,
        auth_url=provider.discovery["token_endpoint"],
        credential="lakekeeper:" + provider.client_secret,
    )
    value = auth.auth_header()
    assert value.startswith("Bearer ")
    token = secret(value.removeprefix("Bearer "))
    return {
        "client": "PyIceberg 0.12.0 LegacyOAuth2AuthManager",
        "segments": len(token.split(".")),
        "scope": "Token acquisition only; NOT a Lakekeeper list/read test",
    }


def human(provider):
    tokens = provider.human()
    header, claims = decode(tokens["access_token"])
    assert claims["iss"] == provider.issuer and claims["exp"] > time.time()
    assert isinstance(claims["sub"], str) and claims["sub"]
    assert claims["aud"] == "lakekeeper" or claims["aud"] == ["lakekeeper"]
    provider.human_token = tokens["access_token"]
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
    assert "lake-readers" in claims.get("groups", []), claims
    return {
        "access_token_groups": claims["groups"],
        "id_token_groups": provider.id_claims.get("groups"),
    }


def id_groups(provider):
    groups = provider.id_claims.get("groups", [])
    expected = "lake-readers@kanidm.idp.test" if provider.name == "kanidm" else "lake-readers"
    assert expected in groups, provider.id_claims
    return {"id_token_groups": groups, "scope": "ID token only; not an API access token"}


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
    provider.rotated_token = token["access_token"]
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


def tls_boundary(provider):
    hostname = provider.hostname
    ports = {8443, 8100, 8200} if provider.name == "rauthy" else {8443}
    pid = json.loads(run("docker", "inspect", provider.container))[0]["State"]["Pid"]
    sockets = run("sudo", "nsenter", "-t", str(pid), "-n", "ss", "-H", "-lnt")
    listeners = [line.split()[3] for line in sockets.splitlines()]
    application = {
        int(address.rsplit(":", 1)[1])
        for address in listeners
        if not address.startswith("127.0.0.11:")
    }
    if application != ports and provider.name == "keycloak":
        # JVM thread dump identifies an unexpected listener without exempting it.
        run("docker", "kill", "--signal=QUIT", provider.container)
    assert application == ports, (application, ports, sockets)
    result = {"listeners": listeners, "ports": {}}
    for port in sorted(ports):
        trusted = ssl.create_default_context(cafile=str(provider.ca))
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with trusted.wrap_socket(sock, server_hostname=hostname) as secure:
                cert = secure.getpeercert()
                version = secure.version()
        errors = {}
        for label, context, target in (
            ("untrusted_ca", ssl.create_default_context(), hostname),
            ("wrong_hostname", trusted, "wrong.idp.test"),
        ):
            try:
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=target):
                        pass
            except ssl.SSLCertVerificationError as exc:
                errors[label] = str(exc)
            else:
                raise AssertionError(label + " accepted")
        # Anonymous cleartext negative; never sends an application credential.
        with socket.create_connection((hostname, port), timeout=10) as sock:
            sock.sendall(b"GET / HTTP/1.0\r\nHost: idp.test\r\n\r\n")
            try:
                reply = sock.recv(4096)
            except ConnectionResetError:
                reply = b""
        # Rustls returns this TLS fatal decode_error alert for a plaintext request.
        assert (
            not reply
            or reply.startswith(b"HTTP/1.1 400 ")
            or reply == b"\x15\x03\x03\x00\x02\x02\x32"
        ), reply
        result["ports"][str(port)] = {
            "tls_version": version,
            "certificate": cert,
            "negative_errors": errors,
            "plaintext_response": repr(reply),
        }
    return result


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
    storage = Storage()
    assert test("storage", storage.start)["status"] == "pass", "Storage fixture failed"
    expiry_tests = []
    for name in ("keycloak", "rauthy", "kanidm"):
        provider = Provider(name, ca)
        started = test(name + "/startup_provision_discovery", lambda: provider.start(arch))
        for case in REQUIRED:
            RESULTS[name + "/" + case] = {
                "status": "blocked",
                "reason": "Provider/catalog prerequisite failed; see setup result",
            }
        if started["status"] != "pass":
            continue
        test(name + "/verified_tls", lambda: tls_boundary(provider))
        test(name + "/machine_token_endpoint", lambda: machine(provider))
        test(name + "/machine_jwt_claims", lambda: machine_claims(provider))
        test(name + "/pyiceberg_token_only", lambda: pyiceberg_token(provider))
        if name == "kanidm":
            test(name + "/service_account_exchange", lambda: exchange(provider))
        test(name + "/human_pkce_idp", lambda: human(provider))
        test(name + "/groups_claim", lambda: groups(provider))
        test(name + "/id_token_groups", lambda: id_groups(provider))
        test(name + "/operations", lambda: operations(provider))

        def setup():
            provider.catalog = Catalog(provider, env, storage)
            return provider.catalog.start()

        if test(name + "/lakekeeper_transport", setup)["status"] != "pass":
            continue
        catalog = provider.catalog
        if (
            test(name + "/seed_table", lambda: catalog.seed(provider.human_token))["status"]
            != "pass"
        ):
            continue
        test(name + "/human_pkce_lakekeeper", lambda: catalog.request(provider.human_token))
        test(name + "/valid_token", lambda: catalog.request(provider.human_token))
        test(
            name + "/machine_token_lakekeeper",
            lambda: catalog.request(provider.client_credentials_token),
        )
        if name == "kanidm":
            test(
                name + "/jwe_rejected",
                lambda: catalog.request(provider.client_credentials_token, 401),
            )
            test(
                name + "/exchange_token_lakekeeper", lambda: catalog.request(provider.machine_token)
            )
        test(
            name + "/different_key",
            lambda: catalog.request(bad_token(provider, "different_key"), 401),
        )
        test(name + "/alg_none", lambda: catalog.request(bad_token(provider, "alg_none"), 401))
        test(name + "/wrong_audience", lambda: catalog.wrong_audience(provider.human_token))
        # Warm the live Lakekeeper JWKS cache before rotating. No restart between these calls.
        catalog.request(provider.human_token)
        test(name + "/rotation_idp", lambda: rotation(provider))
        test(name + "/rotation_lakekeeper", lambda: catalog.request(provider.rotated_token))

        def prepare_expiry():
            # Separate expiry from the rotation test already recorded above. A restart
            # here cannot turn a failed rotation assertion into a pass.
            catalog.restart_backend()
            token = provider.human()["access_token"]
            accepted = catalog.request(token)
            expiry_tests.append((name, catalog, token))
            return {
                "accepted_before_expiry": accepted["http_status"],
                "claims": decode(token)[1],
                "wait_until": decode(token)[1]["exp"] + 61,
            }

        test(name + "/expiry_positive_control", prepare_expiry)
        test(
            name + "/pyiceberg_client_credentials_list_read",
            lambda: catalog.read(catalog.pyiceberg()),
        )
        test(name + "/trino_client_credentials_list_read", lambda: trino(catalog))
        test(name + "/sail_client_credentials_list_read", lambda: sail(catalog))
        # An externally supplied token is a separate diagnostic, never a grant pass.
        if name == "kanidm":
            test(name + "/trino_service_token_exchange", lambda: trino(catalog, "exchange"))
            test(name + "/trino_external_exchange_token", lambda: trino(catalog, "external"))
            test(
                name + "/pyiceberg_external_exchange_token",
                lambda: catalog.read(catalog.pyiceberg(provider.machine_token)),
            )
        else:
            # Use a fresh token; a short-lived Rauthy token may expire during engine startup.
            provider.machine_token = secret(provider.machine().json()["access_token"])
        test(name + "/sail_external_token_list_read", lambda: sail(catalog, external_token=True))
        save("results.json", RESULTS)
    for name, catalog, token in expiry_tests:
        print(name + "/expired_token: waiting for genuine IdP token expiry", flush=True)
        test(name + "/expired_token", lambda: expired(catalog, token))
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
