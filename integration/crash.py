"""T8: single-host container SIGKILL, with a runner-side acknowledgement journal."""

import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
from pathlib import Path

SERVICES = ("postgres", "master", "volume", "filer", "s3", "catalog", "trino")
BATCH_SIZE = 16
RECOVERY_SECONDS = 180


def batch_rows(batch):
    return [[batch, row, f"batch-{batch}-row-{row}"] for row in range(BATCH_SIZE)]


def insert(table, batch):
    values = ", ".join(f"({b}, {r}, '{label}')" for b, r, label in batch_rows(batch))
    return f"INSERT INTO iceberg.integration.{table} VALUES {values}"


def check_batches(rows, attempts, snapshots, initial_snapshot):
    """Exact multi-row atomicity oracle; unknown, duplicate, or missing rows fail."""
    assert len({a["batch"] for a in attempts}) == len(attempts), "Duplicate attempt IDs"
    assert all(a["outcome"] in ("acknowledged", "in-flight") for a in attempts)
    outcomes = {}
    expected = []
    for attempt in attempts:
        batch = attempt["batch"]
        actual = [row for row in rows if row[0] == batch]
        complete = batch_rows(batch)
        assert actual in ([], complete), ("Partial/corrupt batch", batch, actual)
        if attempt["outcome"] == "acknowledged":
            assert actual == complete, ("Lost acknowledged commit", batch)
        visible = "fully-visible" if actual else "absent"
        if "visible" in attempt:
            assert visible == attempt["visible"], ("Outcome changed after settlement", batch)
        outcomes[str(batch)] = visible
        expected.extend(actual)
    assert rows == expected, ("Unexpected/duplicate/out-of-order rows", rows, expected)
    assert initial_snapshot[1:] == [None, "append"], initial_snapshot
    assert snapshots and snapshots[0] == initial_snapshot, snapshots
    assert len(snapshots) == 1 + sum(v == "fully-visible" for v in outcomes.values()), snapshots
    assert len({s[0] for s in snapshots}) == len(snapshots), snapshots
    assert all(s[2] == "append" for s in snapshots), snapshots
    assert [s[1] for s in snapshots] == (
        [None] + [s[0] for s in snapshots[:-1]] if snapshots else []
    ), snapshots
    return outcomes


def snapshot_rows(p, name):
    return p.sql(
        f'SELECT snapshot_id, parent_id, operation FROM iceberg.integration."{name}$snapshots" '
        "ORDER BY committed_at"
    )


def verify(p, manifest):
    """Runs in a fresh interpreter: no cached catalog, Arrow IO, or Trino client."""
    evidence = {}
    for name, spec in manifest.items():
        order = "batch, row_id" if "attempts" in spec else "id"
        rows = p.sql(f"SELECT * FROM iceberg.integration.{name} ORDER BY {order}")
        snapshots = snapshot_rows(p, name)
        table = p.rest_catalog().load_table("integration." + name)
        py_snapshots = [
            [s.snapshot_id, s.parent_snapshot_id, s.summary.operation.value]
            for s in table.metadata.snapshots
        ]
        assert py_snapshots == snapshots, (name, py_snapshots, snapshots)
        # An append-only crash table must have one unbroken chain, no orphan snapshots.
        if "attempts" in spec:
            outcomes = check_batches(rows, spec["attempts"], snapshots, spec["initial_snapshot"])
            assert table.metadata.current_snapshot_id == (snapshots[-1][0] if snapshots else None)
        else:
            assert rows == spec["rows"], (name, rows)
            outcomes = {}
        if "snapshots" in spec:
            assert snapshots == spec["snapshots"], (name, snapshots, spec["snapshots"])
        if name == "encoding_canary":
            reader = p.canary_read()  # Preserve the existing exact decoder contract.
        else:
            arrow = table.scan().to_arrow()
            columns = arrow.column_names
            py_rows = [list(row.values()) for row in arrow.sort_by(order.split(", ")).to_pylist()]
            assert columns == (
                ["batch", "row_id", "label"] if "attempts" in spec else ["id", "label"]
            )
            assert py_rows == rows, (name, py_rows, rows)
            reader = {"rows": len(py_rows), "fresh_process": True}
        evidence[name] = {
            "rows": rows,
            "snapshots": snapshots,
            "snapshot_count": len(snapshots),
            "batch_outcomes": outcomes,
            "pyiceberg": reader,
        }
    return evidence


def fresh_verify(p, manifest, label):
    result = subprocess.run(
        [sys.executable, str(Path(__file__).resolve()), "verify"],
        input=json.dumps(manifest),
        text=True,
        capture_output=True,
        timeout=180,
    )
    (p.REPORTS / f"crash-{label}-reader.log").write_text(result.stdout + result.stderr)
    result.check_returncode()
    evidence = json.loads(
        next(
            line.removeprefix("CRASH_RESULT=")
            for line in result.stdout.splitlines()
            if line.startswith("CRASH_RESULT=")
        )
    )
    # Freeze even ambiguous outcomes: subsequent crashes must preserve this state too.
    for name, spec in manifest.items():
        spec["snapshots"] = evidence[name]["snapshots"]
        for attempt in spec.get("attempts", []):
            attempt["visible"] = evidence[name]["batch_outcomes"][str(attempt["batch"])]
    return evidence


def containers(p, services):
    ids = [p.cid(service) for service in services]
    assert all(ids) and len(set(ids)) == len(services), (services, ids)
    return json.loads(subprocess.check_output(["docker", "inspect", *ids]))


def identity(items):
    return {
        item["Id"]: sorted(
            (m["Name"], m["Destination"]) for m in item["Mounts"] if m["Type"] == "volume"
        )
        for item in items
    }


def kill(p, services, before=None):
    before = containers(p, services) if before is None else before
    assert all(item["State"]["Running"] for item in before)
    started = time.monotonic()
    # One invocation targets all IDs; no stop/down, grace period, or volume removal.
    subprocess.run(["docker", "kill", "--signal=KILL", *[i["Id"] for i in before]], check=True)
    after = json.loads(subprocess.check_output(["docker", "inspect", *[i["Id"] for i in before]]))
    assert all(not i["State"]["Running"] and i["State"]["ExitCode"] == 137 for i in after), after
    return started, identity(before)


def recover(p, services, previous):
    p.compose("start", *services)
    p.hosts()
    assert identity(containers(p, services)) == previous, "Containers/volumes changed"


def settle(p, attempt):
    """Never inspect atomicity while a timed-out query might still commit later."""
    if attempt.get("terminal"):
        return
    query_id = attempt.get("query_id")
    assert query_id, "Submission outcome unknown: cannot prove the query has settled"
    headers = {"X-Trino-User": "integration"}
    status, _ = p.http("DELETE", f"http://trino:8080/v1/query/{query_id}", headers=headers)
    assert status == 204, ("Could not cancel unsettled query", status, query_id)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        status, body = p.http("GET", f"http://trino:8080/v1/query/{query_id}", headers=headers)
        assert status == 200, (status, body)
        if body["state"] in ("FINISHED", "FAILED"):
            attempt["settled_state"] = body["state"]
            return
        time.sleep(0.1)
    raise AssertionError(f"Query {query_id} did not settle")


def create_table(p, table):
    assert (
        p.sql(
            f"CREATE TABLE iceberg.integration.{table} (batch BIGINT, row_id BIGINT, label VARCHAR) "
            "WITH (format='PARQUET', format_version=2)"
        )
        == []
    )
    snapshots = snapshot_rows(p, table)
    assert len(snapshots) == 1 and snapshots[0][1:] == [None, "append"], snapshots
    assert p.sql(f"SELECT * FROM iceberg.integration.{table}") == []
    return {"attempts": [], "initial_snapshot": snapshots[0]}


def component(p, service, manifest, journal):
    table = "crash_" + service
    manifest[table] = create_table(p, table)
    attempts = manifest[table]["attempts"]
    injected = threading.Event()
    before = containers(p, [service])
    restarted = threading.Event()
    stop = threading.Event()
    errors = []
    recovery = {}

    def writer():
        try:
            deadline = time.monotonic() + 2 * RECOVERY_SECONDS
            batch = 0
            while not stop.is_set() and time.monotonic() < deadline:
                batch += 1
                attempt = {"batch": batch, "outcome": "in-flight", "started": time.monotonic()}
                attempts.append(attempt)
                journal("attempt", service=service, **attempt)

                def observe(page):
                    attempt["query_id"] = page["id"]
                    attempt["terminal"] = "nextUri" not in page
                    attempt["state"] = page.get("stats", {}).get("state")

                try:
                    result = p.sql(insert(table, batch), observe=observe)
                except (RuntimeError, urllib.error.URLError, TimeoutError, ConnectionError) as exc:
                    attempt["error"] = str(exc)
                    settle(p, attempt)
                else:
                    assert result == [[BATCH_SIZE]], result
                    attempt["outcome"] = "acknowledged"
                    attempt["acknowledged_at"] = time.monotonic()
                journal("completed", service=service, **attempt)
                if (
                    restarted.is_set()
                    and attempt["started"] >= recovery["restarted_at"]
                    and attempt["outcome"] == "acknowledged"
                ):
                    recovery["new_write_batch"] = batch
                    return
                if not injected.is_set():
                    assert attempt["outcome"] == "acknowledged", "Pre-fault workload failed"
                time.sleep(0.05)
            raise AssertionError("Write workload did not recover within its deadline")
        except BaseException as exc:
            errors.append(exc)

    worker = threading.Thread(target=writer, name="crash-writer")
    worker.start()
    try:
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if errors:
                raise errors[0]
            if len(attempts) >= 3 and sum(a["outcome"] == "acknowledged" for a in attempts) >= 2:
                current = attempts[-1]
                query_id = current.get("query_id")
                if query_id and not current.get("terminal"):
                    status, body = p.http(
                        "GET",
                        f"http://trino:8080/v1/query/{query_id}",
                        headers={"X-Trino-User": "integration"},
                    )
                    # Full query info is unavailable (410) before dispatch completes.
                    assert status in (200, 410), (status, body)
                    if status == 200 and body["state"] == "RUNNING":
                        journal(
                            "running_at_injection",
                            service=service,
                            batch=current["batch"],
                            query_id=query_id,
                            state=body["state"],
                        )
                        injected.set()
                        break
            time.sleep(0.01)
        assert injected.is_set(), "No RUNNING INSERT observed"
        started, previous = kill(p, [service], before)
        journal("killed", service=service, signal="SIGKILL", exit_code=137, containers=previous)
        recover(p, [service], previous)
        recovery["restarted_at"] = time.monotonic()
        restarted.set()
        worker.join(RECOVERY_SECONDS)
        assert not worker.is_alive(), f"{service}: no recovery within {RECOVERY_SECONDS}s"
        if errors:
            raise errors[0]
        assert "new_write_batch" in recovery
        verified = fresh_verify(p, manifest, service)
        recovery["seconds"] = round(time.monotonic() - started, 3)
        assert recovery["seconds"] <= RECOVERY_SECONDS, recovery
        journal("recovered", service=service, **recovery)
        return {**recovery, "attempts": attempts, "verified": verified}
    finally:
        stop.set()
        worker.join(210)
        assert not worker.is_alive(), "Writer remained active after test"


def crash_durability(p):
    journal_lock = threading.Lock()

    def journal(event, **data):
        with journal_lock, (p.REPORTS / "crash-journal.jsonl").open("a") as output:
            output.write(json.dumps({"event": event, "monotonic": time.monotonic(), **data}) + "\n")
            output.flush()
            os.fsync(output.fileno())

    manifest = {}
    for name in ("from_trino", "from_python", "encoding_canary"):
        manifest[name] = {
            "rows": p.sql(f"SELECT * FROM iceberg.integration.{name} ORDER BY id"),
            "snapshots": snapshot_rows(p, name),
        }
    name = "crash_all"
    manifest[name] = create_table(p, name)
    for batch in (1, 2, 3):
        assert p.sql(insert(name, batch)) == [[BATCH_SIZE]]
        attempt = {"batch": batch, "outcome": "acknowledged"}
        manifest[name]["attempts"].append(attempt)
        journal("completed", service="all", **attempt)
    started, previous = kill(p, SERVICES)
    journal("killed", service="all", signal="SIGKILL", exit_code=137, containers=previous)
    recover(p, SERVICES, previous)
    p.wait(
        "Trino after SIGKILL",
        lambda: p.http("GET", "http://trino:8080/v1/info")[1].get("starting") is False,
        180,
    )
    # Only readiness is retried. Exact rows/snapshots/readability assertions run once.
    p.wait(
        "catalog after SIGKILL",
        lambda: (
            p.http("GET", "http://catalog:8181/catalog/v1/config?warehouse=qualification")[0] == 200
        ),
    )
    evidence = {
        "all": {
            "verified": fresh_verify(p, manifest, "all"),
            "seconds": round(time.monotonic() - started, 3),
        }
    }
    p.record("T8_all", evidence["all"])
    for service in ("postgres", "catalog", "volume", "filer"):
        evidence[service] = component(p, service, manifest, journal)
        p.record("T8_" + service, evidence[service])
    p.check_hardening()
    return evidence


if __name__ == "__main__":
    import probe

    assert __debug__, "Assertions must be enabled"
    assert sys.argv[1:] == ["verify"]
    probe.CREDS = json.loads((probe.RUNTIME / "credentials.json").read_text())
    print("CRASH_RESULT=" + json.dumps(verify(probe, json.load(sys.stdin))), flush=True)
