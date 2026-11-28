"""T13: one authenticated whole stack, then the permanent C1–C8 contract."""

import json
import os
import sys
import time
import traceback
from unittest.mock import patch

from auth_fixture import ROOT, cleanup, load

CASES = (
    "login",
    "visibility",
    "rows_masks",
    "grant_revocation",
    "group_revocation",
    "authz_outage",
    "rauthy_outage",
    "audit",
    "tls_isolation",
)


def main(suite):
    common, fixture = load(suite)
    try:
        if suite == "c1-c8":
            import acceptance

            acceptance.evaluate(os.environ["INTEGRATION_ARCH"])
        else:
            whole_stack(common, fixture)
    finally:
        cleanup(common)


def whole_stack(common, fixture):
    import pyarrow as pa
    from acceptance import denial
    from auth_sail import launch
    from auth_trino import start
    from pyiceberg.catalog.rest import RestCatalog

    run, decode, secret, write = common.run, common.decode, common.secret, common.write
    work = common.WORK
    results = {
        "architecture": os.environ["INTEGRATION_ARCH"],
        "run": os.environ["RUN_URL"],
        "pins": json.loads((ROOT / "images.lock.json").read_text()),
        "cases": {case: {"status": "blocked"} for case in CASES},
    }

    def record(name, fn, required=False):
        started = time.monotonic()
        try:
            results["cases"][name] = {"status": "pass", "evidence": fn()}
        except Exception as exc:
            results["cases"][name] = {
                "status": "fail",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }
        results["cases"][name]["seconds"] = time.monotonic() - started
        common.save("results.json", results)
        print(name + ": " + results["cases"][name]["status"], flush=True)
        if required:
            assert results["cases"][name]["status"] == "pass", name

    common.save("results.json", results)
    original = fixture.Rauthy.config_rauthy

    def config(provider):
        value = original(provider)
        path = provider.path / "bootstrap/clients.json"
        clients = json.loads(path.read_text())
        clients += [
            {**clients[0], "id": name, "name": name}
            for name in ("sail-team-a", "sail-team-b", "pyiceberg-service", "trino-catalog")
        ]
        write(path, clients)
        return value

    machines = ("sail-team-a", "sail-team-b", "pyiceberg-service", "trino-catalog")
    with patch.object(fixture.Rauthy, "config_rauthy", config):
        catalog, operator, key = fixture.setup(
            os.environ["INTEGRATION_ARCH"],
            record,
            machine_principals=tuple("oidc~" + name for name in machines),
            extra_catalog_audiences=machines,
        )
    provider = catalog.provider
    tokens = {
        "a": secret(provider.human()["access_token"]),
        "b": secret(
            provider.human(email="bob@idp.test", password=provider.bob_password)["access_token"]
        ),
    }
    users = {name: "oidc~" + decode(token)[1]["sub"] for name, token in tokens.items()}
    team_tokens = {name: provider.token("sail-team-" + name) for name in ("a", "b")}
    machine = provider.token()
    admin = catalog.pyiceberg(operator)
    ids, namespaces = {}, {}
    headers = {"Authorization": "Bearer " + key}

    def mutation(body):
        catalog.http.request(
            "POST", "https://cedar:8443/mutate", headers=headers, json=body
        ).raise_for_status()

    def grant(subject, namespace, remove=False):
        return fixture.grant(catalog, key, subject, "select", namespaces[namespace], remove)

    for name in ("a", "b"):
        namespace = "team_" + name
        admin.create_namespace(namespace)
        namespaces[namespace] = (
            "namespace:" + admin.load_namespace_properties(namespace)["namespace_id"]
        )
        for table in ("sample", "sibling"):
            item = admin.create_table(
                namespace + "." + table, schema=pa.schema([pa.field("id", pa.int64())])
            )
            item.append(pa.Table.from_pylist([{"id": 11 if name == "a" else 22}]))
            ids[namespace, table] = str(item.metadata.table_uuid)
            mutation(
                {
                    "op": "bind_trino",
                    "name": ["iceberg", namespace, table],
                    "binding": {"resource": {"kind": "Table", "id": ids[namespace, table]}},
                }
            )
        group = "lake-readers" if name == "a" else "no-access"
        grant("group:" + group, namespace)
        grant("user:oidc~sail-team-" + name, namespace)
    # Machine clients are read-only and cannot reach the protected rows/masks table.
    grant("user:oidc~lakekeeper", "team_a")
    grant("user:oidc~pyiceberg-service", "team_a")
    # The private connector must load both teams' metadata; OPA independently
    # enforces each authenticated caller's grants. It is not the ingress client.
    grant("user:oidc~trino-catalog", "team_a")
    grant("user:oidc~trino-catalog", "team_b")
    admin.create_namespace("restricted")
    restricted = admin.create_table(
        "restricted.people",
        schema=pa.schema(
            [
                pa.field("id", pa.int64()),
                pa.field("region", pa.string()),
                pa.field("email", pa.string()),
            ]
        ),
    )
    restricted.append(
        pa.Table.from_pylist(
            [
                {"id": 1, "region": "eu", "email": "eu@example.test"},
                {"id": 2, "region": "us", "email": "us@example.test"},
                {"id": 3, "region": "eu", "email": "eu2@example.test"},
            ]
        )
    )
    resource = {"kind": "Table", "id": str(restricted.metadata.table_uuid)}
    mutation(
        {
            "op": "bind_trino",
            "name": ["iceberg", "restricted", "people"],
            "binding": {
                "resource": resource,
                "region_column": "region",
                "sensitive_column": "email",
            },
        }
    )
    mutation({"op": "set_region", "principal": users["a"], "region": "eu"})
    # The authenticated human uses the enforcing engine. Direct/team machines
    # have no grants on restricted.people; static keys remain private scaffolding.
    fixture.grant(
        catalog,
        key,
        "user:" + users["a"],
        "select",
        "lakekeeper_table:" + catalog.warehouse_id + "/" + resource["id"],
    )
    # Trino's private connector identity must load metadata for the restricted table.
    fixture.grant(
        catalog,
        key,
        "user:oidc~trino-catalog",
        "select",
        "lakekeeper_table:" + catalog.warehouse_id + "/" + resource["id"],
    )
    launch(catalog, key, team_tokens)
    sql, trino_tls = start(
        catalog,
        run("sudo", "cat", work / "trino-key").strip(),
        {users[n]: t for n, t in tokens.items()} | {"oidc~lakekeeper": machine},
    )

    def sail(name, query, expected=None, status="OK"):
        result = json.loads(
            run(
                ROOT / ".sources/sail-venv/bin/python",
                ROOT / "integration/auth_sail_query.py",
                input=json.dumps({"token": tokens[name], "sql": query}),
                env=dict(os.environ, GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(provider.ca)),
            )
        )
        assert result["status"] == status, result
        if status == "OK":
            assert result["rows"] == expected, result
        return result

    def sail_denied(name, query):
        result = json.loads(
            run(
                ROOT / ".sources/sail-venv/bin/python",
                ROOT / "integration/auth_sail_query.py",
                input=json.dumps({"token": tokens[name], "sql": query}),
                env=dict(os.environ, GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(provider.ca)),
            )
        )
        assert result["status"] in ("INTERNAL", "UNKNOWN", "INVALID_ARGUMENT"), result
        detail = result.get("detail", "")
        assert any(
            s in detail
            for s in ("403 Forbidden", "404 Not Found", "CannotSee", "does not exist", "not found")
        ), result
        assert not any(
            s in detail for s in ("401 Unauthorized", "Connection refused", "TLS", "Syntax error")
        ), result
        return result

    def trino_rows(user, query, expected):
        result = sql(user, query)
        assert result == {"rows": expected}, result
        return result

    def trino_denied(user, query):
        result = sql(user, query)
        assert result.get("error", {}).get("errorName") == "PERMISSION_DENIED", result
        assert result["error"]["errorType"] == "USER_ERROR", result
        return {"errorName": result["error"]["errorName"]}

    def rest(name, namespace="team_a", table="sample"):
        return catalog.http.request(
            "GET",
            catalog.base
            + f"/catalog/v1/{catalog.warehouse_id}/namespaces/{namespace}/tables/{table}",
            headers={"Authorization": "Bearer " + tokens[name]},
        )

    def login():
        for name, token in tokens.items():
            claims = decode(token)[1]
            assert claims["iss"] == provider.issuer and claims["aud"] == "lakekeeper", claims
            assert rest(name, "team_" + name).status_code == 200
        reader = RestCatalog(
            "t13-machine",
            **{
                "uri": catalog.base + "/catalog",
                "warehouse": catalog.warehouse,
                "ssl": {"cabundle": str(provider.ca)},
                "credential": "pyiceberg-service:" + provider.client_secrets["pyiceberg-service"],
                "oauth2-server-uri": provider.discovery["token_endpoint"],
                "scope": "openid profile",
                "header.X-Iceberg-Access-Delegation": "client-managed",
                **catalog.storage.properties(),
            },
        )
        assert reader.list_namespaces() == [("team_a",)], reader.list_namespaces()
        assert reader.load_table("team_a.sample").scan().to_arrow().to_pylist() == [{"id": 11}]
        denied = denial(lambda: reader.load_table("team_b.sample"))
        connector = catalog.pyiceberg(provider.token("trino-catalog"))
        assert connector.load_table("team_b.sample").scan().to_arrow().to_pylist() == [{"id": 22}]
        connector_denied = denial(lambda: connector.load_table("denied.sample"))
        return {
            "human": "Rauthy authorization code with S256 PKCE; JWT to all three services",
            "pyiceberg": {"rows": [{"id": 11}], "other_namespace": denied},
            "trino_machine_other": trino_denied(
                "oidc~lakekeeper", "SELECT * FROM iceberg.team_b.sample"
            ),
            "trino_machine": trino_rows(
                "oidc~lakekeeper", "SELECT id FROM iceberg.team_a.sample", [[11]]
            ),
            "private_connector": {"team_b_rows": [{"id": 22}], "outside_union": connector_denied},
            "sail": "independent client-credentials token file per team",
            "trino_tls": trino_tls,
        }

    record("login", login)

    def visibility():
        evidence = {}
        for name, value in (("a", 11), ("b", 22)):
            other = "b" if name == "a" else "a"
            reader = catalog.pyiceberg(tokens[name])
            expected_namespaces = [("restricted",), ("team_a",)] if name == "a" else [("team_b",)]
            assert sorted(reader.list_namespaces()) == expected_namespaces, reader.list_namespaces()
            assert sorted(reader.list_tables("team_" + name)) == [
                ("team_" + name, "sample"),
                ("team_" + name, "sibling"),
            ]
            assert reader.load_table("team_" + name + ".sample").scan().to_arrow().to_pylist() == [
                {"id": value}
            ]
            evidence[name] = {
                "catalog_other": denial(lambda: reader.load_table("team_" + other + ".sample")),
                "trino_namespaces": trino_rows(
                    users[name],
                    "SHOW SCHEMAS FROM iceberg",
                    [["restricted"], ["team_a"]] if name == "a" else [["team_b"]],
                ),
                "trino_tables": trino_rows(
                    users[name], "SHOW TABLES FROM iceberg.team_" + name, [["sample"], ["sibling"]]
                ),
                "trino_rows": trino_rows(
                    users[name], "SELECT id FROM iceberg.team_" + name + ".sample", [[value]]
                ),
                "trino_other": trino_denied(
                    users[name], "SELECT * FROM iceberg.team_" + other + ".sample"
                ),
                "trino_write": trino_denied(
                    users[name], "INSERT INTO iceberg.team_" + name + ".sample VALUES (99)"
                ),
                "sail_tables": sail(
                    name,
                    "SHOW TABLES IN bakeoff.team_" + name,
                    [
                        {"database": "team_" + name, "tableName": t, "isTemporary": False}
                        for t in ("sample", "sibling")
                    ],
                ),
                "sail_rows": sail(
                    name, "SELECT id FROM bakeoff.team_" + name + ".sample", [{"id": value}]
                ),
                "sail_other": sail_denied(name, "SELECT * FROM bakeoff.team_" + other + ".sample"),
                "sail_write": sail_denied(
                    name, "INSERT INTO bakeoff.team_" + name + ".sample VALUES (99)"
                ),
            }
        return evidence

    record("visibility", visibility)

    def rows_masks():
        masked = trino_rows(
            users["a"],
            "SELECT id, region, email FROM iceberg.restricted.people ORDER BY id",
            [[1, "eu", None], [3, "eu", None]],
        )
        for name in ("a", "b"):
            reader = catalog.pyiceberg(team_tokens[name])
            denial(lambda: reader.load_table("restricted.people"))
            sail_denied(name, "SELECT * FROM bakeoff.restricted.people")
        return {"exact_rows_and_null_masks": masked, "team_direct_access": "denied"}

    record("rows_masks", rows_masks)

    def grant_revocation():
        # Revoke the team's machine grant as well as the human group grant.
        # Each probe starts a fresh Spark session; already admitted/cached data
        # is outside the upstream gateway's revocation contract.
        grant("group:lake-readers", "team_a", True)
        acknowledged = grant("user:oidc~sail-team-a", "team_a", True)
        try:
            response = rest("a")
            assert response.status_code in (403, 404), response.status_code
            trino = trino_denied(users["a"], "SELECT id FROM iceberg.team_a.sample")
            denied = sail_denied("a", "SELECT id FROM bakeoff.team_a.sample")
            seconds = time.monotonic() - acknowledged
            assert seconds < 5, seconds
            assert decode(tokens["a"])[1]["exp"] > time.time()
            return {
                "seconds_since_ack": seconds,
                "catalog": response.status_code,
                "trino": trino,
                "sail": denied,
                "old_tokens": True,
            }
        finally:
            grant("group:lake-readers", "team_a")
            grant("user:oidc~sail-team-a", "team_a")

    record("grant_revocation", grant_revocation)

    def group_revocation():
        subject = decode(tokens["a"])[1]["sub"]
        url = provider.base + "/auth/v1/users/" + subject
        original_user = catalog.http.json("GET", url, headers=provider.admin)
        try:
            removed = provider.remove_group(subject)
            assert not removed.get("groups"), removed
            acknowledged = time.monotonic()
            time.sleep(0.3)
            response = rest("a")
            assert response.status_code in (403, 404), response.status_code
            trino = trino_denied(users["a"], "SELECT id FROM iceberg.team_a.sample")
            gateway = sail("a", "SELECT 42 AS answer", status="PERMISSION_DENIED")
            seconds = time.monotonic() - acknowledged
            assert seconds < 5, seconds
            assert decode(tokens["a"])[1]["exp"] > time.time()
            sail("a", "SELECT 42 AS answer", status="PERMISSION_DENIED")
            sail("b", "SELECT 42 AS answer", [{"answer": 42}])
            return {
                "seconds_since_ack": seconds,
                "catalog": response.status_code,
                "trino": trino,
                "sail": gateway,
                "old_token_repeated": True,
            }
        finally:
            catalog.http.json("PUT", url, headers=provider.admin, json=original_user)
            time.sleep(0.3)

    record("group_revocation", group_revocation)

    def outage(target):
        assert rest("a").status_code == 200
        trino_rows(users["a"], "SELECT id FROM iceberg.team_a.sample", [[11]])
        sail("a", "SELECT id FROM bakeoff.team_a.sample", [{"id": 11}])
        run("docker", "stop", "-t", "5", target)
        try:
            time.sleep(0.3)
            response = rest("a")
            assert response.status_code in (403, 500, 503), response.status_code
            body = response.json()
            assert body.get("error", {}).get("type"), body
            assert not any(k in body for k in ("metadata", "config", "storage-credentials")), body
            trino = sql(users["a"], "SELECT id FROM iceberg.team_a.sample")
            assert "rows" not in trino and "error" in trino, trino
            # Dependency failures must have the real OPA failure, never a timeout.
            assert "io.trino.plugin.opa.OpaQueryException" in json.dumps(trino), trino
            gateway = sail("a", "SELECT 42 AS answer", status="UNAVAILABLE")
        finally:
            run("docker", "start", target)
        common.wait(
            lambda: (
                provider.http.request("GET", provider.base + "/auth/v1/health").status_code == 200
            ),
            180,
        )
        common.wait(lambda: rest("a").status_code == 200)
        recovered = {
            "trino": trino_rows(users["a"], "SELECT id FROM iceberg.team_a.sample", [[11]]),
            "sail": sail("a", "SELECT id FROM bakeoff.team_a.sample", [{"id": 11}]),
            "other_catalog": rest("a", "team_b").status_code,
        }
        assert recovered["other_catalog"] in (403, 404), recovered
        return {
            "catalog_status": response.status_code,
            "catalog_error": body["error"]["type"],
            "trino_error": trino["error"]["errorName"],
            "sail": gateway,
            "recovered": recovered,
        }

    record("authz_outage", lambda: outage("cedar"))
    record("rauthy_outage", lambda: outage(provider.container))
    from auth_audit import audit, isolation

    record("tls_isolation", lambda: isolation(catalog))
    record("audit", lambda: audit(catalog, users))
    assert all(results["cases"][case]["status"] == "pass" for case in CASES), (
        "T13 incomplete; see sanitized evidence"
    )


if __name__ == "__main__":
    assert __debug__, "Assertions must be enabled"
    main(sys.argv[1])
