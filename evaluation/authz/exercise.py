"""C1–C8: stable backend acceptance contract, identical on both native CPUs."""

import os
import platform
import time

from common import WORK, decode, run, save, wait
from fixture import BACKEND_NETWORK, INPUTS, setup

RESULTS = {}
CASES = tuple(f"C{i}" for i in range(1, 9))


def initialize(arch):
    RESULTS["run"] = {
        "architecture": arch,
        "uname": platform.machine(),
        "url": os.environ["RUN_URL"],
    }
    for case in CASES:
        RESULTS[case] = {"status": "blocked", "reason": "Fixture prerequisites have not completed"}
    save("results.json", RESULTS)


def record(name, fn, required=False):
    start = time.monotonic()
    try:
        result = {"status": "pass", "value": fn()}
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


def write_denials(reader):
    import pyarrow as pa

    table = reader.load_table("bakeoff.sample")
    return {
        "create_namespace": denial(lambda: reader.create_namespace("forbidden")),
        "create_table": denial(
            lambda: reader.create_table(
                "bakeoff.no", schema=pa.schema([pa.field("id", pa.int64())])
            )
        ),
        "append": denial(
            lambda: table.append(pa.Table.from_pylist([{"id": 3, "label": "forbidden"}]))
        ),
        "overwrite": denial(
            lambda: table.overwrite(pa.Table.from_pylist([{"id": 3, "label": "forbidden"}]))
        ),
        "delete": denial(lambda: table.delete("id = 1")),
        "commit": denial(
            lambda: table.transaction().set_properties(test="denied").commit_transaction()
        ),
        "drop": denial(lambda: reader.drop_table("bakeoff.sample")),
        "rename": denial(lambda: reader.rename_table("bakeoff.sample", "bakeoff.renamed")),
    }


def evaluate(arch):
    initialize(arch)
    catalog, operator, key = setup(arch, record)
    provider, http = catalog.provider, catalog.http
    human = provider.human()["access_token"]
    provider.human_token = human
    claims = decode(human)[1]
    assert "lake-readers" in claims["groups"]
    admin = catalog.pyiceberg(operator)
    namespace = "namespace:" + admin.load_namespace_properties("bakeoff")["namespace_id"]
    headers = {"Authorization": "Bearer " + key}
    stores = http.json("GET", "https://openfga:8080/stores", headers=headers)["stores"]
    store = next(s["id"] for s in stores if s["name"] == "lakekeeper")
    base = f"https://openfga:8080/stores/{store}"
    models = http.json("GET", base + "/authorization-models", headers=headers)[
        "authorization_models"
    ]
    model = models[0]["id"]
    save("openfga-model.json", models[0])

    def tuples(user, relation, obj, delete=False):
        http.json(
            "POST",
            base + "/write",
            headers=headers,
            json={
                "authorization_model_id": model,
                "deletes" if delete else "writes": {
                    "tuple_keys": [{"user": user, "relation": relation, "object": obj}]
                },
            },
        )

    human_id = "user:oidc~" + claims["sub"]
    reader = None

    def grants():
        nonlocal reader
        tuples(human_id, "select", namespace)
        reader = catalog.pyiceberg(human)
        namespaces = reader.list_namespaces()
        assert namespaces == [("bakeoff",)], namespaces
        return {
            "namespaces": namespaces,
            "allowed": catalog.read(reader),
            "other_list": denial(lambda: reader.list_tables("denied")),
            "other_read": denial(lambda: reader.load_table("denied.sample")),
            "writes": write_denials(reader),
        }

    record("C1", grants)

    def inheritance():
        import pyarrow as pa

        later = admin.create_table("bakeoff.later", schema=pa.schema([pa.field("id", pa.int64())]))
        later.append(pa.Table.from_pylist([{"id": 7}]))
        try:
            assert set(reader.list_tables("bakeoff")) == {
                ("bakeoff", "sample"),
                ("bakeoff", "later"),
            }
            assert reader.load_table("bakeoff.later").scan().to_arrow().to_pylist() == [{"id": 7}]
        finally:
            admin.drop_table("bakeoff.later")
        admin.create_namespace("single")
        for name in ("one", "sibling"):
            table = admin.create_table(
                "single." + name, schema=pa.schema([pa.field("id", pa.int64())])
            )
            table.append(pa.Table.from_pylist([{"id": 8}]))
        table_id = str(admin.load_table("single.one").metadata.table_uuid)
        # The same genuine human subject has only a single-table grant in this namespace.
        tuples(human_id, "select", "table:" + table_id)
        assert reader.load_table("single.one").scan().to_arrow().to_pylist() == [{"id": 8}]
        try:
            listed = reader.list_tables("single")
            assert listed == [("single", "one")], listed
        except Exception as exc:
            from pyiceberg.exceptions import ForbiddenError, NoSuchNamespaceError

            assert isinstance(exc, (ForbiddenError, NoSuchNamespaceError)), exc
            listed = type(exc).__name__
        return {
            "namespace_covers_new_table": True,
            "single_table_rows": [{"id": 8}],
            "single_table_list": listed,
            "sibling": denial(lambda: reader.load_table("single.sibling")),
        }

    record("C2", inheritance)

    def groups():
        tuples(human_id, "select", namespace, True)
        # Register a Lakekeeper role, then grant to its OpenFGA userset.
        role = http.json(
            "POST",
            catalog.base + "/management/v1/role",
            statuses=(200, 201),
            headers={"Authorization": "Bearer " + operator},
            json={"name": "lake-readers", "description": "C3 authoritative group sync"},
        )
        role_id = role.get("id", role.get("role-id"))
        assert role_id, role
        role_obj = "role:" + role_id
        tuples(role_obj + "#assignee", "select", namespace)
        negative = denial(lambda: catalog.read(catalog.pyiceberg(human)))
        user_url = provider.base + "/auth/v1/users/" + claims["sub"]

        def sync():
            user = provider.http.json("GET", user_url, headers=provider.admin)
            member = "lake-readers" in (user.get("groups") or [])
            tuples(human_id, "assignee", role_obj, delete=not member)
            return {"source": "Rauthy admin API over verified TLS", "member": member}

        added = sync()
        assert added["member"]
        allowed = catalog.read(catalog.pyiceberg(human))
        provider.remove_group(claims["sub"])
        removed = sync()
        assert not removed["member"]
        # Even the old, still-valid groups-bearing JWT must lose access after sync.
        denied = denial(lambda: catalog.read(catalog.pyiceberg(human)))
        tuples(role_obj + "#assignee", "select", namespace, True)
        tuples(human_id, "select", namespace)
        return {
            "claims_alone_denied": negative,
            "sync_added": added,
            "allowed": allowed,
            "sync_removed": removed,
            "old_token_denied": denied,
            "boundary": "One-group explicit sync; no production reconciler or polling SLA",
        }

    record("C3", groups)

    def revoke():
        catalog.read(catalog.pyiceberg(human))
        tuples(human_id, "select", namespace, True)
        acknowledged = time.monotonic()
        samples = []
        while time.monotonic() - acknowledged < 30:
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
                    "first_denial_seconds": samples[-1]["seconds_since_ack"],
                    "samples": samples,
                    "scope": "Delete acknowledgment to first fresh REST denial; issued storage credentials excluded",
                }
            time.sleep(0.1)
        raise AssertionError({"revocation_not_seen_within_seconds": 30, "samples": samples})

    record("C4", revoke)
    tuples("user:oidc~lakekeeper", "select", namespace)

    def machines():
        from engines import sail, trino

        def pyiceberg():
            client = catalog.pyiceberg()
            return {
                "allowed": catalog.read(client),
                "other_read": denial(lambda: client.load_table("denied.sample")),
                "writes": write_denials(client),
            }

        outcomes = {
            "pyiceberg": record("C5.pyiceberg", pyiceberg),
            "trino": record("C5.trino", lambda: trino(catalog)),
            "sail": record("C5.sail", lambda: sail(catalog)),
        }
        assert all(r["status"] == "pass" for r in outcomes.values()), outcomes
        return outcomes

    record("C5", machines)

    def credentials():
        token = provider.token()
        base = catalog.base + f"/catalog/v1/{catalog.warehouse_id}/namespaces/"
        auth = {
            "Authorization": "Bearer " + token,
            "X-Iceberg-Access-Delegation": "vended-credentials",
        }
        denied = http.request("GET", base + "denied/tables/sample", headers=auth)
        assert denied.status_code in (403, 404), (denied.status_code, denied.text)
        assert not any(
            k in denied.text
            for k in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token")
        ), denied.text
        allowed = http.json("GET", base + "bakeoff/tables/sample", headers=auth)
        config = allowed.get("config", {})
        credential_blocks = allowed.get("storage-credentials", [])
        for block in credential_blocks:
            assert not any(
                k in block.get("config", {})
                for k in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token")
            ), block
        # Phase C retains sts-enabled=false. Record exactly the config names, never key material.
        assert not any(
            k in config for k in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token")
        ), list(config)
        return {
            "denied_status": denied.status_code,
            "denied_credentials": False,
            "read_only_config_keys": sorted(config),
            "storage_credential_config_keys": [
                sorted(block.get("config", {})) for block in credential_blocks
            ],
            "sts_enabled": False,
            "scope": "Read grant, no STS keys with this profile; source scopes documented separately",
        }

    record("C6", credentials)
    from security import evaluate as security

    record("C7", lambda: security(catalog, operator, human, namespace, tuples))

    def operations():
        before = http.json("POST", base + "/read", headers=headers, json={})
        run("docker", "restart", "openfga")
        wait(
            lambda: (
                http.request("GET", "https://openfga:8080/stores", headers=headers).status_code
                == 200
            )
        )
        after = http.json("POST", base + "/read", headers=headers, json={})
        assert sorted(before["tuples"], key=str) == sorted(after["tuples"], key=str), (
            before,
            after,
        )
        catalog.read(catalog.pyiceberg())
        denial(lambda: catalog.pyiceberg().load_table("denied.sample"))
        for _ in range(2):
            run(
                "docker",
                "run",
                "--rm",
                "--label",
                "datopsis.idp-bakeoff=true",
                "--network",
                BACKEND_NETWORK,
                "--env-file",
                WORK / "fga-migration.env",
                "-v",
                f"{provider.ca}:/ca/ca.pem:ro",
                INPUTS["openfga"]["image"],
                "migrate",
            )
            run(
                "docker",
                "run",
                "--rm",
                "--label",
                "datopsis.idp-bakeoff=true",
                "--network",
                "container:" + catalog.proxy,
                "--env-file",
                catalog.env,
                "-v",
                f"{provider.ca}:/ca/ca.pem:ro",
                "localhost/lakekeeper-ubi:integration",
                "migrate",
            )
        final = http.json("POST", base + "/read", headers=headers, json={})
        assert sorted(before["tuples"], key=str) == sorted(final["tuples"], key=str)
        assert not before.get("continuation_token"), "Tuple comparison must cover all pages"
        catalog.read(catalog.pyiceberg())
        denial(lambda: catalog.pyiceberg().load_table("denied.sample"))
        return {
            "grants_preserved": True,
            "tuple_count": len(final["tuples"]),
            "migration_repetitions": 2,
            "post_restart_and_migration_allow_deny": True,
        }

    record("C8", operations)
    record("unchanged_rows", lambda: catalog.read(admin), required=True)
    assert all(RESULTS[case]["status"] == "pass" for case in CASES), (
        "Incomplete acceptance; see results.json"
    )
