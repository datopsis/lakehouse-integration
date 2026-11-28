"""Durable decision records and private transport boundaries in disposable T13."""

import json
from collections import Counter
from urllib.parse import unquote, urlsplit

from common import WORK, run, write
from fixture import BACKEND_NETWORK, backend_address, transport


def audit(catalog, users):
    database = urlsplit(run("sudo", "cat", WORK / "cedar-db-url").strip())
    values = {
        "PGHOST": database.hostname,
        "PGPORT": str(database.port or 5432),
        "PGDATABASE": unquote(database.path.lstrip("/")),
        "PGUSER": unquote(database.username),
        "PGPASSWORD": unquote(database.password),
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": "/ca/ca.pem",
    }
    write(WORK / "audit.env", "".join(k + "=" + v + "\n" for k, v in values.items()))

    def sql(query):
        return json.loads(
            run(
                "docker",
                "run",
                "--rm",
                "-i",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--network",
                "container:fga-postgres",
                "--env-file",
                WORK / "audit.env",
                "-v",
                f"{catalog.provider.ca}:/ca/ca.pem:ro",
                "localhost/postgresql-lakekeeper-ubi:integration",
                "psql",
                "-XqAt",
                "-v",
                "ON_ERROR_STOP=1",
                "-f",
                "-",
                input=query,
            )
        )

    rows = sql(
        "SELECT coalesce(json_agg(row_to_json(a) ORDER BY id),'[]'::json) FROM authz_audit a;"
    )
    assert rows and all(
        set(row) >= {"id", "principal", "action", "resource", "decision", "policy_ids", "reason"}
        for row in rows
    )
    assert len({row["id"] for row in rows}) == len(rows)
    for user in (
        *users.values(),
        "oidc~sail-team-a",
        "oidc~sail-team-b",
        "oidc~pyiceberg-service",
        "oidc~lakekeeper",
        "oidc~trino-catalog",
    ):
        matching = [r for r in rows if r["principal"] == user]
        assert any(r["decision"] for r in matching), user
        assert any(not r["decision"] for r in matching), user
    events = [
        json.loads(line)
        for line in run("docker", "logs", "gateway").splitlines()
        if line.startswith("{") and "sail_admission" in line
    ]
    observed = Counter(str(e["grpc_status"]) + ":sail:" + e["team"] for e in events)
    admissions = [r for r in rows if r["action"] == "sail:admit"]
    persisted = Counter(
        str(r["result"]["grpc_status"]) + ":" + r["resource"]["id"] for r in admissions
    )
    assert events and observed == persisted, (observed, persisted)
    opa = [r for r in rows if r["action"].startswith("trino:")]
    assert opa and all(r["result"] is not None for r in opa), opa
    assert any(r["result"] == {"result": [{"expression": "\"region\" = 'eu'"}]} for r in opa)
    assert any("NULL" in json.dumps(r["result"]) for r in opa)
    before = sql(
        "SELECT json_build_object('count',count(*),'digest',md5(string_agg(row_to_json(a)::text,'' ORDER BY id))) FROM authz_audit a;"
    )
    run("docker", "restart", "fga-postgres")
    from common import wait

    wait(lambda: run("docker", "exec", "fga-postgres", "pg_isready", "-h", "fga-postgres"))
    after = sql(
        "SELECT json_build_object('count',count(*),'digest',md5(string_agg(row_to_json(a)::text,'' ORDER BY id))) FROM authz_audit a;"
    )
    assert before == after, (before, after)
    # Trigger oracles run against this fixture's isolated DB only.
    for statement in (
        "UPDATE authz_audit SET reason=reason",
        "DELETE FROM authz_audit",
        "TRUNCATE authz_audit",
    ):
        query = f"DO $$ BEGIN {statement}; RAISE EXCEPTION 'mutation unexpectedly succeeded'; EXCEPTION WHEN raise_exception THEN IF SQLERRM <> 'authorization audit is append-only' THEN RAISE; END IF; END $$; SELECT to_json(true);"
        assert sql(query) is True
    return {
        "records": len(rows),
        "exact_gateway_records": len(admissions),
        "opa_records": len(opa),
        "all_fixture_principals_allow_and_deny": True,
        "postgres_restart": after,
        "append_only": True,
    }


def isolation(catalog):
    from common import NETWORK

    result = {"gateway_tls": transport("sail", 50051, catalog.provider.ca)}
    for name in ("a", "b"):
        obj = json.loads(run("docker", "inspect", "sail-" + name))[0]
        assert not obj["HostConfig"]["PortBindings"]
        assert obj["HostConfig"]["ReadonlyRootfs"] and obj["Config"]["User"] != "0"
        mounts = obj["Mounts"]
        assert [m["Destination"] for m in mounts if "token" in m["Destination"]] == [
            "/run/team-token"
        ]
        assert not any(
            "/socket" in m["Destination"] or "/teams" in m["Destination"] for m in mounts
        )
        address = obj["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
        code = int(
            run(
                "docker",
                "run",
                "--rm",
                "--read-only",
                "--cap-drop=ALL",
                "--network",
                NETWORK,
                "--entrypoint",
                "/usr/bin/python3.12",
                "localhost/sail-ubi:integration",
                "-c",
                f"import socket; s=socket.socket(); s.settimeout(3); print(s.connect_ex(({address!r},50052)))",
            )
        )
        assert code == 111, code
        stat = json.loads(
            run(
                "docker",
                "exec",
                "sail-" + name,
                "/usr/bin/python3.12",
                "-c",
                'import os,json; s=os.stat("/run/team-token"); print(json.dumps([s.st_uid,s.st_mode&511]))',
            )
        )
        assert stat == [10001, 256], stat
        assert BACKEND_NETWORK not in obj["NetworkSettings"]["Networks"]
        code = int(
            run(
                "docker",
                "exec",
                "sail-" + name,
                "/usr/bin/python3.12",
                "-c",
                f"import socket; s=socket.socket(); s.settimeout(3); print(s.connect_ex(({backend_address()!r},8443)))",
            )
        )
        assert code in (101, 110, 111, 113), code
        result[name] = {
            "loopback_peer_refused": True,
            "token_uid_mode": stat,
            "serve_unreachable_errno": code,
        }
    return result
