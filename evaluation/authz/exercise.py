"""Identical native assertions. Failed capability requirements remain failed."""

import os
import platform
import subprocess
import time

from common import WORK, decode, run, save
from fixture import setup

RESULTS = {}


def record(name, fn, required=False):
    start = time.monotonic()
    try:
        value = fn()
        result = {"status": "pass", "value": value}
    except Exception as exc:
        result = {"status": "fail", "error_type": type(exc).__name__, "error": str(exc)}
    result["seconds"] = round(time.monotonic() - start, 4)
    RESULTS[name] = result
    save("results.json", RESULTS)
    print(name + ": " + result["status"], flush=True)
    if required:
        assert result["status"] == "pass", result
    return result


def denial(fn):
    from pyiceberg.exceptions import ForbiddenError, NoSuchNamespaceError, NoSuchTableError

    try:
        fn()
    except (ForbiddenError, NoSuchNamespaceError, NoSuchTableError) as exc:
        return {"type": type(exc).__name__, "message": str(exc)}
    raise AssertionError("Denied operation succeeded")


def evaluate(arch):
    RESULTS["run"] = {
        "architecture": arch,
        "uname": platform.machine(),
        "url": os.environ["RUN_URL"],
    }
    required = (
        "human_read",
        "human_other_namespace",
        "human_write",
        "token_groups",
        "explicit_role_membership",
        "revocation",
        "machine_pyiceberg",
        "machine_trino",
        "cedar_policy_point",
    )
    for name in required:
        RESULTS[name] = {"status": "blocked", "reason": "Fixture prerequisites have not completed"}
    save("results.json", RESULTS)
    catalog, operator, key = setup(arch, record)
    provider = catalog.provider
    human = provider.human()["access_token"]
    claims = decode(human)[1]
    assert "lake-readers" in claims["groups"]
    record("human_claims", lambda: claims)
    from cedar import evaluate as cedar

    record("cedar_policy_point", lambda: cedar(arch, catalog, human))
    admin = catalog.pyiceberg(operator)
    ns_id = admin.load_namespace_properties("bakeoff")["namespace_id"]
    http = catalog.http
    headers = {"Authorization": "Bearer " + key}
    stores = http.json("GET", "https://openfga:8080/stores", headers=headers)["stores"]
    store = next(s["id"] for s in stores if s["name"] == "lakekeeper")
    base = f"https://openfga:8080/stores/{store}"
    models = http.json("GET", base + "/authorization-models", headers=headers)[
        "authorization_models"
    ]
    model = models[0]["id"]

    def tuples(user, relation, obj, delete=False):
        body = {
            "authorization_model_id": model,
            "deletes" if delete else "writes": {
                "tuple_keys": [{"user": user, "relation": relation, "object": obj}]
            },
        }
        http.json("POST", base + "/write", headers=headers, statuses=(200,), json=body)

    human_id = "user:oidc~" + claims["sub"]
    namespace = "namespace:" + ns_id
    # First test token-only group membership, with no stored assignee tuple.
    role = "role:00000000-0000-0000-0000-000000000123"
    tuples(role + "#assignee", "select", namespace)

    def group_claim():
        reader = catalog.pyiceberg(human)
        return catalog.read(reader)

    record("token_groups", group_claim)
    # A separately labelled workaround: explicit membership stored in OpenFGA.
    tuples(human_id, "assignee", role)
    record("explicit_role_membership", group_claim)
    tuples(human_id, "assignee", role, True)
    tuples(role + "#assignee", "select", namespace, True)
    tuples(human_id, "select", namespace)
    reader = catalog.pyiceberg(human)
    record("human_read", lambda: catalog.read(reader))
    record(
        "human_other_namespace",
        lambda: {
            "list": denial(lambda: reader.list_tables("denied")),
            "read": denial(lambda: reader.load_table("denied.sample")),
        },
    )

    def writes():
        import pyarrow as pa

        return {
            "create": denial(
                lambda: reader.create_table(
                    "bakeoff.no", schema=pa.schema([pa.field("id", pa.int64())])
                )
            ),
            "commit": denial(
                lambda: (
                    reader.load_table("bakeoff.sample").update_properties(test="denied").commit()
                )
            ),
        }

    record("human_write", writes)

    def revoke():
        catalog.read(reader)
        started = time.monotonic()
        tuples(human_id, "select", namespace, True)
        acknowledged = time.monotonic()
        samples = []
        deadline = acknowledged + 30
        while time.monotonic() < deadline:
            response = http.request(
                "GET",
                catalog.base
                + f"/catalog/v1/{catalog.warehouse_id}/namespaces/bakeoff/tables/sample",
                headers={"Authorization": "Bearer " + human},
            )
            samples.append(
                {
                    "seconds_since_ack": time.monotonic() - acknowledged,
                    "status": response.status_code,
                }
            )
            assert response.status_code in (200, 403, 404), (response.status_code, response.text)
            if response.status_code in (403, 404):
                return {
                    "write_seconds": acknowledged - started,
                    "first_denial_seconds": samples[-1]["seconds_since_ack"],
                    "samples": samples,
                    "scope": "Fresh REST loads; cached data/credentials not revoked",
                }
            time.sleep(0.1)
        raise AssertionError({"revocation_not_seen_within_seconds": 30, "samples": samples})

    record("revocation", revoke)
    tuples("user:oidc~lakekeeper", "select", namespace)

    def machine():
        client = catalog.pyiceberg()
        return {
            "allowed": catalog.read(client),
            "read_denied": denial(lambda: client.load_table("denied.sample")),
            "write_denied": denial(
                lambda: (
                    client.load_table("bakeoff.sample").update_properties(test="denied").commit()
                )
            ),
        }

    record("machine_pyiceberg", machine)
    from engines import trino

    record("machine_trino", lambda: trino(catalog))
    # No denied write may have altered the fixture.
    record("unchanged_rows", lambda: catalog.read(admin))

    def operations():
        pids = run("docker", "top", "openfga", "-eo", "pid").splitlines()[1:]
        rss = sum(
            int(
                next(
                    line.split()[1]
                    for line in run("sudo", "cat", f"/proc/{p.strip()}/status").splitlines()
                    if line.startswith("VmRSS:")
                )
            )
            for p in pids
        )
        # Back up the authorization database through its local trusted Unix socket.
        backup = WORK / "openfga.sql"
        with backup.open("w") as output:
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "idp-postgres",
                    "pg_dump",
                    "-h",
                    "/tmp",
                    "-U",
                    "postgres",
                    "openfga",
                ],
                stdout=output,
                check=True,
            )
        backup.chmod(0o600)
        run(
            "docker",
            "exec",
            "idp-postgres",
            "createdb",
            "-h",
            "/tmp",
            "-U",
            "postgres",
            "openfga_restore",
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
            "-v",
            "ON_ERROR_STOP=1",
            "-d",
            "openfga_restore",
            input=backup.read_text(),
        )
        counts = {}
        for db in ("openfga", "openfga_restore"):
            counts[db] = run(
                "docker",
                "exec",
                "idp-postgres",
                "psql",
                "-XAt",
                "-h",
                "/tmp",
                "-U",
                "postgres",
                "-d",
                db,
                "-c",
                "SELECT count(*) FROM tuple",
            )
        assert counts["openfga"] == counts["openfga_restore"]
        return {
            "rss_kib": rss,
            "backup_bytes": backup.stat().st_size,
            "tuple_counts": counts,
            "restore_scope": "SQL restore and tuple count; no HA/failover or restored-service decision test",
        }

    record("operations", operations)
    assert all(RESULTS[name]["status"] == "pass" for name in required), (
        "Incomplete qualification; see results.json"
    )
