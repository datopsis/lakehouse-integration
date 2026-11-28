"""Typed Spark Connect authentication oracle; tokens only enter through files."""

import json
import os
import sys
import uuid
from pathlib import Path

import grpc
import pyarrow as pa
from pyspark.sql.connect.proto import base_pb2, base_pb2_grpc

endpoint, token_file, expected = sys.argv[1:]
token = Path(token_file).read_text().strip() if token_file != "-" else ""
channel = grpc.secure_channel(
    endpoint,
    grpc.ssl_channel_credentials(
        root_certificates=Path(os.environ["GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"]).read_bytes()
    ),
)
stub = base_pb2_grpc.SparkConnectServiceStub(channel)
request = base_pb2.ExecutePlanRequest(session_id=str(uuid.uuid4()))
request.user_context.user_id = "client-controlled-user"
request.plan.root.sql.query = "SELECT 42 AS answer"
metadata = [("authorization", "Bearer " + token)] if token else []
try:
    responses = list(stub.ExecutePlan(request, metadata=metadata, timeout=20))
    assert expected == "OK", "Rejected-token operation succeeded"
    batches = [
        pa.ipc.open_stream(r.arrow_batch.data).read_all()
        for r in responses
        if r.HasField("arrow_batch")
    ]
    assert batches and pa.concat_tables(batches).to_pylist() == [{"answer": 42}], "Incorrect result"
    print(json.dumps(dict(code="OK", rows=[{"answer": 42}], result_batches=len(batches))))
except grpc.RpcError as error:
    assert error.code().name == expected, (error.code().name, expected)
    print(json.dumps(dict(code=error.code().name)))
finally:
    channel.close()
