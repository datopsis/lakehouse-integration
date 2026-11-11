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
