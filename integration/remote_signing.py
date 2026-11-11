"""Remote-signing restart diagnostics, isolated from the static-credential path."""

import json
import re
import socket
import threading
import time
from contextlib import ExitStack
from unittest.mock import patch

from gates import EXPECTED_ROWS, redact


def sanitize(text, values):
    text = redact(text, values)
    text = re.sub(r"(?i)(Signature=)[0-9a-f]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:Calculated|Provided): )[0-9a-f]+", r"\1[REDACTED]", text)
    return re.sub(r"(?i)(Bearer )[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)


class RestartDiagnostic:
    def __init__(self, factory, reports, credentials):
        self.factory = factory
        self.path = reports / "remote-signing.jsonl"
        self.values = list(credentials.values())
        self.lock = threading.Lock()
        self.phase = "before"
        self.stack = ExitStack()

    def emit(self, kind, **data):
        entry = {"phase": self.phase, "kind": kind, "time": time.time(), **data}
        with self.lock, self.path.open("a") as stream:
            stream.write(sanitize(json.dumps(entry, default=str), self.values) + "\n")

    def start(self):
        import requests
        from aiobotocore.httpsession import AIOHTTPSession

        send = requests.Session.send
        aio_send = AIOHTTPSession.send
        diagnostic = self

        def traced_send(session, request, **kwargs):
            response = send(session, request, **kwargs)
            diagnostic.emit(
                "rest",
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                body=request.body,
                status=response.status_code,
                response=response.text,
            )
            return response

        async def traced_aio(session, request):
            response = await aio_send(session, request)
            diagnostic.emit(
                "s3",
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
                status=response.status_code,
                response_headers=dict(response.headers),
                error=(await response.content).decode() if response.status_code >= 400 else None,
            )
            return response

        self.stack.enter_context(patch.object(requests.Session, "send", traced_send))
        self.stack.enter_context(patch.object(AIOHTTPSession, "send", traced_aio))
        self.catalog = self.factory("remote-signing", False)
        self.table = self.catalog.load_table("integration.from_trino")
        self.properties = dict(self.table.io.properties)
        assert self.properties["s3.signer"] == "S3V4RestSigner"
        assert not any(
            self.properties.get(key)
            for key in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token", "token")
        )
        self.emit("properties", properties=self.properties)
        return self.read(self.table)

    def read(self, table):
        self.emit("dns", addresses={name: socket.gethostbyname(name) for name in ("catalog", "s3")})
        rows = table.scan().to_arrow().sort_by("id").to_pylist()
        assert rows == EXPECTED_ROWS, rows
        self.emit("rows", rows=rows)
        return rows

    def after(self):
        results = {}
        try:
            for label, load in (
                ("same_table", lambda: self.table),
                ("reload_table", lambda: self.catalog.load_table("integration.from_trino")),
                (
                    "new_catalog",
                    lambda: self.factory("remote-signing", False).load_table(
                        "integration.from_trino"
                    ),
                ),
            ):
                self.phase = label
                try:
                    table = load()
                    self.emit(
                        "properties",
                        properties=table.io.properties,
                        same=table.io.properties == self.properties,
                    )
                    results[label] = {"rows": self.read(table)}
                except Exception as exc:
                    results[label] = {"error": str(exc), "type": type(exc).__name__}
                    self.emit("failure", **results[label])
            assert all("rows" in result for result in results.values()), results
            return results
        finally:
            self.stack.close()
