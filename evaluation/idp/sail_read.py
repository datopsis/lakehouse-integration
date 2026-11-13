"""Run with the owning Sail repository's hash-locked Spark client environment."""

import json
import os

from pyspark.sql import SparkSession

spark = SparkSession.builder.remote(os.environ["SAIL_TEST_URL"]).getOrCreate()
try:
    tables = [list(row) for row in spark.sql("SHOW TABLES IN bakeoff.bakeoff").collect()]
    assert len(tables) == 1 and tables[0][1] == "sample", tables
    rows = [
        list(row)
        for row in spark.sql("SELECT id, label FROM bakeoff.bakeoff.sample ORDER BY id").collect()
    ]
    assert rows == [[1, "alpha"], [2, "beta"]], rows
    print("SAIL_RESULT=" + json.dumps({"tables": tables, "rows": rows}), flush=True)
finally:
    spark.stop()
