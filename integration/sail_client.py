"""One fresh Spark Connect session per invocation; runs in Sail's isolated venv."""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Verified TLS through the Sail proxy. The run CA must be configured before gRPC
# initializes; a bare sc:// URL would be plaintext and is never used.
REMOTE = "sc://sail:50051/;use_ssl=true"


def session(remote=REMOTE):
    roots = os.environ["GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"]
    assert Path(roots).is_file(), "Run CA missing; refusing to use default trust"
    # The exact owner-approved retry/reattach policy from the pinned sail-ubi
    # source (docs/TLS.md): one retry of only the documented INTERNAL stream reset.
    sys.path.insert(0, str(ROOT / ".sources/sail-ubi/examples"))
    from spark_connect_retry import ResetRetry

    sys.path.pop(0)
    from pyspark.sql import SparkSession

    spark = SparkSession.builder.remote(remote).getOrCreate()
    spark.client.enable_reattachable_execute()
    spark.client.set_retry_policies([ResetRetry()])
    return spark


def main():
    spark = session()
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
