"""Real Spark Connect queries with attacker-controlled session/user identity fields."""

import concurrent.futures
import json
import os
import sys
import time
import uuid
from pathlib import Path

import grpc
import pyarrow as pa
from pyspark.sql.connect.proto import base_pb2, base_pb2_grpc


def query(token, sql, session=None, expected=None, endpoint="sail:50051", tls=True):
    channel = (
        grpc.secure_channel(
            endpoint,
            grpc.ssl_channel_credentials(
                root_certificates=Path(os.environ["GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"]).read_bytes()
            ),
        )
        if tls
        else grpc.insecure_channel(endpoint)
    )
    stub = base_pb2_grpc.SparkConnectServiceStub(channel)
    request = base_pb2.ExecutePlanRequest(session_id=session or str(uuid.uuid4()))
    request.user_context.user_id = "another-user-controlled-by-client"
    request.plan.root.sql.query = sql
    started = time.monotonic()
    try:
        responses = list(
            stub.ExecutePlan(request, metadata=[("authorization", "Bearer " + token)], timeout=90)
        )
        tables = [
            pa.ipc.open_stream(r.arrow_batch.data).read_all()
            for r in responses
            if r.HasField("arrow_batch")
        ]
        rows = pa.concat_tables(tables).to_pylist() if tables else []
        assert expected is None or expected == rows, (expected, rows)
        return dict(status="OK", seconds=time.monotonic() - started, rows=rows)
    except grpc.RpcError as exc:
        # Preserve typed transport status + engine error. Errors are never reads.
        return dict(
            status=exc.code().name, seconds=time.monotonic() - started, detail=exc.details()
        )
    finally:
        channel.close()


if __name__ == "__main__":
    request = json.load(sys.stdin)
    if "jobs" in request:
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            results = list(pool.map(lambda job: query(**job), request["jobs"]))
        print(json.dumps(results))
    else:
        print(json.dumps(query(**request)))
