"""One fresh Spark Connect session per invocation; runs in Sail's isolated venv."""

import json
import sys

from pyspark.sql import SparkSession


def main():
    spark = SparkSession.builder.remote("sc://sail:50051").getOrCreate()
    try:
        catalogs = sorted(row[0] for row in spark.sql("SHOW CATALOGS").collect())
        print("SAIL CATALOGS=" + json.dumps(catalogs), flush=True)
        # 0.7.3 always registers its built-in system catalog as well.
        assert catalogs == ["qualification", "system"], catalogs
        assert spark.sql("SELECT current_catalog()").collect()[0][0] == "qualification"
        results = []
        for query in json.load(sys.stdin):
            rows = [list(row) for row in spark.sql(query).collect()]
            print("SAIL SQL " + query + " => " + json.dumps(rows), flush=True)
            results.append(rows)
        print("SAIL_RESULT=" + json.dumps(results), flush=True)
    finally:
        spark.stop()


if __name__ == "__main__":
    main()
