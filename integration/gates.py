"""Small fail-closed gates shared by the runner and regression tests."""

DECODER_ERROR = (
    "Not yet implemented: DecodeArrow of DictAccumulator for DeltaLengthByteArrayDecoder."
)
EXPECTED_ROWS = [{"id": 1, "label": "alpha"}, {"id": 2, "label": "updated"}]


def encoding_read(read):
    try:
        rows = read()
    except OSError as exc:
        if str(exc) != DECODER_ERROR:
            raise
        return {"status": "expected-failure", "error": str(exc)}
    assert rows == EXPECTED_ROWS, rows
    return {"status": "upstream-fixed", "rows": rows}


def redact(text, values):
    for value in sorted(values, key=len, reverse=True):
        if value:
            text = text.replace(value, "[REDACTED]")
    return text


def remote_signing_failure(exc, operation, code, message):
    """Accept only the measured S3 denial, never arbitrary permission errors."""
    from botocore.exceptions import ClientError

    assert type(exc) is PermissionError and str(exc) == message, repr(exc)
    cause = exc.__cause__
    assert isinstance(cause, ClientError), repr(cause)
    assert cause.operation_name == operation, cause
    if operation == "HeadObject":
        assert cause.response["Error"] == {"Code": code, "Message": message}, cause.response
    assert cause.response["Error"]["Code"] == code, cause.response
    assert cause.response["Error"]["Message"] == message, cause.response
    assert cause.response["ResponseMetadata"]["HTTPStatusCode"] == 403, cause.response
