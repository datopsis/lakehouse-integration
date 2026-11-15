"""C7: signature, identity, time, audience, network isolation and fail closed."""

import errno
import json
import sys
import time

from catalog import b64, bad_token
from common import decode, run, secret, wait
from fixture import BACKEND_NETWORK, container


def evaluate(catalog, operator, human, namespace, tuples):
    provider, http = catalog.provider, catalog.http
    endpoint = catalog.base + f"/catalog/v1/{catalog.warehouse_id}/namespaces/denied/tables/sample"
    positive = http.request("GET", endpoint, headers={"Authorization": "Bearer " + operator})
    assert positive.status_code == 200, positive.text
    identity = {}
    for header in ("X-Trino-User", "X-Iceberg-User", "X-User-Id", "X-Forwarded-User"):
        response = http.request(
            "GET",
            endpoint,
            headers={
                "Authorization": "Bearer " + human,
                header: "oidc~" + decode(operator)[1]["sub"],
            },
        )
        assert response.status_code in (403, 404), (response.status_code, response.text)
        identity[header] = response.status_code
    # Changing sub while keeping the genuine signature must be rejected, too.
    parts = human.split(".")
    claims = decode(human)[1]
    forged_subject = secret(
        parts[0] + "." + b64({**claims, "sub": decode(operator)[1]["sub"]}) + "." + parts[2]
    )
    invalid = {}
    for name, token in (
        ("altered_subject", forged_subject),
        ("wrong_signature", bad_token(provider, "different_key")),
        ("wrong_audience", provider.token("wrong-audience")),
    ):
        response = http.request(
            "GET", catalog.base + "/catalog/v1/config", headers={"Authorization": "Bearer " + token}
        )
        assert response.status_code == 401, (name, response.status_code, response.text)
        invalid[name] = response.status_code
    expiry = provider.token("expiry")
    # A genuine signed expiry token is first accepted at whoami, independent of grants.
    whoami = catalog.base + "/management/v1/whoami"
    accepted = http.request("GET", whoami, headers={"Authorization": "Bearer " + expiry})
    assert accepted.status_code == 200, (accepted.status_code, accepted.text)
    deadline = decode(expiry)[1]["exp"] + 61
    while time.time() <= deadline:
        time.sleep(min(5, deadline - time.time() + 1))
    rejected = http.request("GET", whoami, headers={"Authorization": "Bearer " + expiry})
    assert rejected.status_code == 401, (rejected.status_code, rejected.text)
    fresh = http.request(
        "GET", whoami, headers={"Authorization": "Bearer " + provider.token("expiry")}
    )
    assert fresh.status_code == 200, fresh.text
    invalid["genuine_expired_token"] = {"before": 200, "after": 401, "fresh": 200}
    address = json.loads(run("docker", "inspect", "openfga"))[0]["NetworkSettings"]["Networks"][
        BACKEND_NETWORK
    ]["IPAddress"]
    container(
        "pyiceberg-client-net",
        "localhost/sail-ubi:integration",
        ["-c", "import time; time.sleep(600)"],
        extra=["--entrypoint", "/usr/bin/python3.12"],
    )
    isolation = {}
    for name in ("trino", "sail", "pyiceberg-client-net"):
        obj = json.loads(run("docker", "inspect", name))[0]
        assert BACKEND_NETWORK not in obj["NetworkSettings"]["Networks"], name
        statuses = {}
        for port in (8080, 8081):
            script = f"import socket; s=socket.socket(); s.settimeout(3); print(s.connect_ex(({address!r}, {port})))"
            code = int(
                run(
                    "sudo",
                    "nsenter",
                    "-t",
                    str(obj["State"]["Pid"]),
                    "-n",
                    sys.executable,
                    "-c",
                    script,
                )
            )
            assert code in (
                errno.ECONNREFUSED,
                errno.ETIMEDOUT,
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
            ), (name, port, code)
            statuses[str(port)] = code
        isolation[name] = statuses
    allowed = catalog.base + f"/catalog/v1/{catalog.warehouse_id}/namespaces/bakeoff/tables/sample"
    auth = {"Authorization": "Bearer " + provider.token()}
    assert http.request("GET", allowed, headers=auth).status_code == 200
    run("docker", "stop", "-t", "10", "openfga")
    try:
        response = http.request("GET", allowed, headers=auth)
        assert response.status_code in (403, 500, 503), (response.status_code, response.text)
        error = response.json()["error"]
        assert error.get("type"), error
        assert "metadata" not in response.json() and "config" not in response.json(), response.text
        failure = {"status": response.status_code, "error": error}
    finally:
        run("docker", "start", "openfga")
    wait(lambda: http.request("GET", allowed, headers=auth).status_code == 200, 120)
    catalog.read(catalog.pyiceberg())
    denied = http.request("GET", endpoint, headers=auth)
    assert denied.status_code in (403, 404), denied.text
    return {
        "identity_header_denials": identity,
        "tokens": invalid,
        "network_isolation": isolation,
        "backend_stopped": failure,
        "recovered_allow": 200,
        "recovered_deny": denied.status_code,
    }
