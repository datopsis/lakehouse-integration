"""Real Sail 0.7.3 authorization controls, in its owner hash-locked client venv."""

import json

from pyspark.errors import PySparkException
from pyspark.sql import SparkSession

spark = SparkSession.builder.remote("sc://sail:50051/;use_ssl=true").getOrCreate()
try:
    tables = [list(r) for r in spark.sql("SHOW TABLES IN bakeoff.bakeoff").collect()]
    assert len(tables) == 1 and tables[0][1] == "sample", tables
    rows = [
        list(r)
        for r in spark.sql("SELECT id, label FROM bakeoff.bakeoff.sample ORDER BY id").collect()
    ]
    assert rows == [[1, "alpha"], [2, "beta"]], rows
    negatives = {}
    for query in (
        "SELECT * FROM bakeoff.denied.sample",
        "INSERT INTO bakeoff.bakeoff.sample VALUES (3, 'forbidden')",
        "UPDATE bakeoff.bakeoff.sample SET label='forbidden' WHERE id=1",
        "DELETE FROM bakeoff.bakeoff.sample WHERE id=1",
        "CREATE TABLE bakeoff.bakeoff.forbidden (id BIGINT) USING iceberg",
        "DROP TABLE bakeoff.bakeoff.sample",
    ):
        try:
            spark.sql(query).collect()
        except PySparkException as exc:
            message = str(exc)
            assert any(
                s in message
                for s in (
                    "403 Forbidden",
                    "404 Not Found",
                    "CannotSee",
                    "does not exist",
                    "not found",
                )
            ), message
            assert not any(
                s in message
                for s in ("401 Unauthorized", "Connection refused", "TLS", "Syntax error")
            ), message
            negatives[query] = message
        else:
            raise AssertionError("Denied Sail request succeeded: " + query)
    print(
        "SAIL_RESULT=" + json.dumps({"tables": tables, "rows": rows, "denials": negatives}),
        flush=True,
    )
finally:
    spark.stop()
