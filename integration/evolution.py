"""T12: schema identity, old-file projection and historical snapshots in three clients."""

import copy
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

TABLE = "iceberg.integration.evolution"
SAIL_TABLE = "qualification.integration.evolution"
# Field IDs are part of the oracle: rename/widen preserve them; new fields get new IDs.
INITIAL = [
    [1, "id", "int"],
    [2, "label", "string"],
    [3, "obsolete", "string"],
    [4, "details", [[5, "code", "int"]]],
]
# Only measured, exact failures belong here. Unknown errors always fail the gate.
SAIL_ERRORS = {}


def normalized(value):
    if isinstance(value, dict):
        return [normalized(v) for v in value.values()]
    if isinstance(value, (tuple, list)):
        return [normalized(v) for v in value]
    return value


def trino_type(kind):
    if isinstance(kind, list):
        return "row(" + ", ".join(f"{name} {trino_type(t)}" for _, name, t in kind) + ")"
    return {"int": "integer", "long": "bigint", "string": "varchar"}[kind]


def spark_schema(fields):
    return {
        "type": "struct",
        "fields": [
            {
                "name": name,
                "type": spark_schema(kind)
                if isinstance(kind, list)
                else {"int": "integer", "long": "long", "string": "string"}[kind],
                "nullable": True,
                "metadata": {},
            }
            for _, name, kind in fields
        ],
    }


def iceberg_schema(fields):
    from pyiceberg.schema import Schema
    from pyiceberg.types import IntegerType, LongType, NestedField, StringType, StructType

    def field(spec):
        field_id, name, kind = spec
        field_type = (
            StructType(*(field(child) for child in kind))
            if isinstance(kind, list)
            else {"int": IntegerType(), "long": LongType(), "string": StringType()}[kind]
        )
        return NestedField(field_id, name, field_type, required=False)

    return Schema(*(field(spec) for spec in fields))


def client(h, mode, specs, label):
    executable = str(h.ROOT / ".sources/sail-venv/bin/python") if mode == "sail" else sys.executable
    result = subprocess.run(
        [executable, str(Path(__file__).resolve()), mode],
        input=json.dumps(specs),
        text=True,
        capture_output=True,
        timeout=180,
    )
    (h.REPORTS / f"evolution-{label}-{mode}.log").write_text(result.stdout + result.stderr)
    result.check_returncode()
    return json.loads(
        next(
            line.removeprefix("EVOLUTION_RESULT=")
            for line in result.stdout.splitlines()
            if line.startswith("EVOLUTION_RESULT=")
        )
    )


def trino_read(h, query, fields, rows):
    columns = []

    def observe(page):
        if "columns" in page:
            columns[:] = [[c["name"], c["type"]] for c in page["columns"]]

    actual = h.sql(query, observe=observe)
    assert columns == [[name, trino_type(kind)] for _, name, kind in fields], columns
    assert actual == rows, (query, actual, rows)
    return {"schema": columns, "rows": actual}


def sail_outcome(result, fields, rows, label):
    if "schema" in result:
        assert result["schema"] == spark_schema(fields), (label, result)
    if "error" in result:
        expected = SAIL_ERRORS.get(label)
        return {
            **result,
            "status": "expected-failure" if result["error"] == expected else "unexpected-error",
        }
    assert result["rows"] == rows, (label, result, rows)
    assert "schema" in result
    status = "pass"
    if label in SAIL_ERRORS:
        status = "upstream-fixed"
        notice = f"Sail {label} now reads the exact T12 schema and rows; review and retire its failure canary."
        print("::notice title=Sail evolution canary passed::" + notice, flush=True)
        if os.environ.get("GITHUB_STEP_SUMMARY"):
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
                output.write("\n**" + notice + "**\n")
    return {**result, "status": status}


def current(h, label, fields, rows, evidence):
    query = f"SELECT * FROM {TABLE} ORDER BY id"
    trino = trino_read(h, query, fields, rows)
    spec = {"fields": fields, "rows": rows}
    python = client(h, "pyiceberg", [spec], label)[0]
    sail = client(h, "sail", [{"query": query.replace(TABLE, SAIL_TABLE)}], label)[0]
    result = {"trino": trino, "pyiceberg": python, "sail": sail_outcome(sail, fields, rows, label)}
    evidence[label] = result
    h.record("T12_" + label, result)
    return python


def exercise(h):
    assert (
        h.sql(
            f"CREATE TABLE {TABLE} (id INTEGER, label VARCHAR, obsolete VARCHAR, details ROW(code INTEGER)) "
            "WITH (format='PARQUET', format_version=2)"
        )
        == []
    )
    assert h.sql(
        f"INSERT INTO {TABLE} VALUES (1, 'alpha', 'old-a', ROW(10)), (2, 'beta', 'old-b', ROW(20))"
    ) == [[2]]
    fields = copy.deepcopy(INITIAL)
    rows = [[1, "alpha", "old-a", [10]], [2, "beta", "old-b", [20]]]
    evidence = {}
    snapshots = []

    def checkpoint(label):
        python = current(h, label, fields, rows, evidence)
        snapshots.append(
            {
                "label": label,
                "fields": copy.deepcopy(fields),
                "rows": copy.deepcopy(rows),
                "snapshot_id": python["snapshot_id"],
                "timestamp_ms": python["timestamp_ms"],
            }
        )

    checkpoint("initial")
    steps = [
        ("add", "ADD COLUMN note VARCHAR", "(3, 'gamma', 'old-c', ROW(30), 'new-3')"),
        ("rename", "RENAME COLUMN label TO title", "(4, 'delta', 'old-d', ROW(40), 'new-4')"),
        ("drop", "DROP COLUMN obsolete", "(5, 'epsilon', ROW(50), 'new-5')"),
        (
            "widen",
            "ALTER COLUMN id SET DATA TYPE BIGINT",
            "(2147483648, 'wide', ROW(60), 'new-wide')",
        ),
        (
            "nested",
            "ADD COLUMN details.extra VARCHAR",
            "(2147483649, 'nested', ROW(70, 'nested-new'), 'new-nested')",
        ),
    ]
    for label, ddl, inserted in steps:
        assert h.sql(f"ALTER TABLE {TABLE} {ddl}") == []
        if label == "add":
            fields.append([6, "note", "string"])
            rows = [row + [None] for row in rows]
            new_row = [3, "gamma", "old-c", [30], "new-3"]
        elif label == "rename":
            fields[1][1] = "title"
            new_row = [4, "delta", "old-d", [40], "new-4"]
        elif label == "drop":
            fields.pop(2)
            rows = [row[:2] + row[3:] for row in rows]
            new_row = [5, "epsilon", [50], "new-5"]
        elif label == "widen":
            fields[0][2] = "long"
            new_row = [2147483648, "wide", [60], "new-wide"]
        else:
            fields[2][2].append([7, "extra", "string"])
            rows = [row[:2] + [row[2] + [None]] + row[3:] for row in rows]
            new_row = [2147483649, "nested", [70, "nested-new"], "new-nested"]
        unchanged = current(h, label + "_ddl", fields, rows, evidence)
        assert unchanged["snapshot_id"] == snapshots[-1]["snapshot_id"], (
            "Schema-only commit created a data snapshot"
        )
        assert h.sql(f"INSERT INTO {TABLE} VALUES {inserted}") == [[1]]
        rows.append(new_row)
        checkpoint(label)

    assert len({s["snapshot_id"] for s in snapshots}) == 6
    assert all(a["timestamp_ms"] < b["timestamp_ms"] for a, b in zip(snapshots, snapshots[1:]))
    travel = {}
    for snapshot in snapshots:
        label = snapshot["label"]
        fields, rows = snapshot["fields"], snapshot["rows"]
        timestamp = datetime.fromtimestamp(snapshot["timestamp_ms"] / 1000, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )[:-3]
        trino = {}
        for mode, clause in (
            ("version", f"FOR VERSION AS OF {snapshot['snapshot_id']}"),
            ("timestamp", f"FOR TIMESTAMP AS OF TIMESTAMP '{timestamp} UTC'"),
        ):
            trino[mode] = trino_read(h, f"SELECT * FROM {TABLE} {clause} ORDER BY id", fields, rows)
        python = client(h, "pyiceberg", [snapshot], "travel-" + label)[0]
        spark_time = timestamp.replace("T", " ").replace("+00:00", "")
        queries = [
            {
                "query": f"SELECT * FROM {SAIL_TABLE} VERSION AS OF {snapshot['snapshot_id']} ORDER BY id"
            },
            {"query": f"SELECT * FROM {SAIL_TABLE} TIMESTAMP AS OF '{spark_time}' ORDER BY id"},
        ]
        sail = client(h, "sail", queries, "travel-" + label)
        travel[label] = {
            "snapshot": snapshot,
            "trino": trino,
            "pyiceberg": python,
            "sail": {
                mode: sail_outcome(result, fields, rows, "travel_" + mode + "_" + label)
                for mode, result in zip(("version", "timestamp"), sail, strict=True)
            },
        }
        h.record("T12_travel_" + label, travel[label])
    outcomes = [value["sail"] for value in evidence.values()]
    outcomes += [outcome for value in travel.values() for outcome in value["sail"].values()]
    assert all(o["status"] != "unexpected-error" for o in outcomes), outcomes
    return {"evolution": evidence, "time_travel": travel}


def pyiceberg_reader(specs):
    import probe as h

    h.CREDS = json.loads((h.RUNTIME / "credentials.json").read_text())
    results = []
    for spec in specs:
        table = h.rest_catalog().load_table("integration.evolution")
        assert not table.io.properties.get("s3.signer")
        assert table.metadata.format_version == 2
        snapshot_id = spec.get("snapshot_id")
        scan = table.scan(snapshot_id=snapshot_id)
        expected = iceberg_schema(spec["fields"])
        assert scan.projection().fields == expected.fields, (scan.projection(), expected)
        arrow = scan.to_arrow().sort_by("id")
        rows = normalized(arrow.to_pylist())
        assert rows == spec["rows"], (rows, spec)
        snapshot = table.snapshot_by_id(snapshot_id) if snapshot_id else table.current_snapshot()
        results.append(
            {
                "schema": str(scan.projection()),
                "rows": rows,
                "snapshot_id": snapshot.snapshot_id,
                "timestamp_ms": snapshot.timestamp_ms,
                "fresh_process": os.getpid(),
            }
        )
    return results


def sail_reader(specs):
    from pyspark.sql import SparkSession

    spark = SparkSession.builder.remote("sc://sail:50051").getOrCreate()
    try:
        assert sorted(row[0] for row in spark.sql("SHOW CATALOGS").collect()) == [
            "qualification",
            "system",
        ]
        results = []
        for spec in specs:
            result = {"query": spec["query"]}
            try:
                frame = spark.sql(spec["query"])
                result["schema"] = frame.schema.jsonValue()
                result["rows"] = normalized(frame.collect())
            except Exception as exc:
                # Capture evidence, not an exemption. Parent accepts only an exact,
                # measured per-query error; all unknown errors fail the final gate.
                result["error"] = {
                    "type": type(exc).__module__ + "." + type(exc).__name__,
                    "message": str(exc),
                }
            results.append(result)
        return results
    finally:
        spark.stop()


if __name__ == "__main__":
    assert __debug__, "Assertions must be enabled"
    assert sys.argv[1:] in (["pyiceberg"], ["sail"])
    specs = json.load(sys.stdin)
    result = sail_reader(specs) if sys.argv[1] == "sail" else pyiceberg_reader(specs)
    print("EVOLUTION_RESULT=" + json.dumps(result), flush=True)
