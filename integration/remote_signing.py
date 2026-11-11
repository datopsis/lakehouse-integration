"""Remote-signing restart diagnostics, isolated from the static-credential path."""

import json
import os
import re
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from unittest.mock import patch
from urllib.parse import urlsplit

from gates import EXPECTED_ROWS, redact, remote_signing_failure


def sanitize(text, values):
    text = redact(text, values)
    text = redact(text, [value[:4] + "***" for value in values if len(value) >= 4])
    text = re.sub(r"(?i)(Signature=)[0-9a-f]+", r"\1[REDACTED]", text)
    text = re.sub(r"(?i)((?:Calculated|Provided): )[0-9a-f]+", r"\1[REDACTED]", text)
    return re.sub(r"(?i)(Bearer )[A-Za-z0-9._~+/=-]+", r"\1[REDACTED]", text)


class RestartDiagnostic:
    def __init__(self, factory, reports, credentials):
        self.factory = factory
        self.path = reports / "remote-signing.jsonl"
        self.values = list(credentials.values())
        self.access_key = credentials["access"]
        self.lock = threading.Lock()
        self.phase = "before"
        self.entries = []
        self.stack = ExitStack()

    def emit(self, kind, **data):
        entry = {"phase": self.phase, "kind": kind, "time": time.time(), **data}
        with self.lock, self.path.open("a") as stream:
            self.entries.append(entry)
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
            headers = {
                key: value.decode() if isinstance(value, bytes) else value
                for key, value in request.headers.items()
            }
            lower = {key.lower(): value for key, value in headers.items()}
            if response.status_code in (200, 206):
                assert "Credential=" + diagnostic.access_key + "/" in lower["authorization"]
                assert "SignedHeaders=" in lower["authorization"]
                assert "x-amz-security-token" not in lower
                signed_at = datetime.strptime(lower["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(
                    tzinfo=timezone.utc
                )
                server_at = parsedate_to_datetime(response.headers["date"])
                assert abs((server_at - signed_at).total_seconds()) < 60
            diagnostic.emit(
                "s3",
                method=request.method,
                url=request.url,
                headers=headers,
                host=urlsplit(request.url).netloc,
                status=response.status_code,
                response_headers=dict(response.headers),
                error=(await response.content).decode() if response.status_code >= 400 else None,
            )
            return response

        self.stack.enter_context(patch.object(requests.Session, "send", traced_send))
        self.stack.enter_context(patch.object(AIOHTTPSession, "send", traced_aio))
        # Serialization is a control experiment, not the canary: the separate
        # barrier below forces the actual concurrent upstream initialization gap.
        from pyiceberg.utils.concurrent import ExecutorFactory

        pool = self.stack.enter_context(ThreadPoolExecutor(max_workers=1))
        self.stack.enter_context(patch.object(ExecutorFactory, "_instance", pool))
        self.stack.enter_context(patch.object(ExecutorFactory, "_instance_pid", os.getpid()))
        self.catalog = self.factory("remote-signing", False)
        self.table = self.catalog.load_table("integration.from_trino")
        self.properties = dict(self.table.io.properties)
        assert self.properties["s3.signer"] == "S3V4RestSigner"
        assert not any(
            self.properties.get(key)
            for key in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token", "token")
        )
        self.emit("properties", properties=self.properties)
        rows = self.read(self.table)
        tasks = list(self.table.scan().plan_files())
        assert any(task.delete_files for task in tasks)
        self.path_to_read = next(file.file_path for task in tasks for file in task.delete_files)
        self.fs = self.table.io.get_fs("s3")
        return rows

    def read(self, table):
        self.emit("dns", addresses={name: socket.gethostbyname(name) for name in ("catalog", "s3")})
        rows = table.scan().to_arrow().sort_by("id").to_pylist()
        assert rows == EXPECTED_ROWS, rows
        self.emit("rows", rows=rows)
        return rows

    def race(self):
        """Pause real PyIceberg initialization between unregister/register.

        Never remove a handler ourselves. If upstream stops unregistering or
        stops sharing filesystems, signed success must surface as upstream-fixed.
        """
        from pyiceberg.io.fsspec import FsspecFileIO

        events = self.fs.s3.meta.events
        original = events.unregister
        removed = threading.Event()
        release = threading.Event()
        finished = threading.Event()
        worker = {}

        def unregister(event_name, *args, **kwargs):
            result = original(event_name, *args, **kwargs)
            if event_name == "before-sign.s3" and kwargs.get("unique_id") == 1925:
                removed.set()
                assert release.wait(30), "Reader did not release signer initialization"
            return result

        def initialize():
            try:
                worker["fs"] = FsspecFileIO(dict(self.properties)).get_fs("s3")
            except BaseException as exc:
                worker["error"] = exc
            finally:
                finished.set()
                removed.set()  # Also wake the reader if upstream removed this gap.

        start = len(self.entries)
        with patch.object(events, "unregister", unregister):
            thread = threading.Thread(target=initialize, name="T9-fileio-initializer")
            thread.start()
            try:
                assert removed.wait(30), "FileIO initialization did not reach barrier"
                if "error" in worker:
                    raise worker["error"]
                self.emit("interleaving", initializer_finished=finished.is_set())
                try:
                    with self.table.io.new_input(self.path_to_read).open() as source:
                        assert source.read(4) == b"PAR1"
                except PermissionError as exc:
                    remote_signing_failure(exc, "HeadObject", "403", "Forbidden")
                    # HEAD has no error body. Ask the same unsigned client for the
                    # same object with GET to retain SeaweedFS's precise reason.
                    try:
                        self.fs.cat_file(self.path_to_read, start=0, end=4)
                    except PermissionError as get_error:
                        remote_signing_failure(
                            get_error, "GetObject", "AccessDenied", "Access Denied."
                        )
                    else:
                        raise AssertionError("Unsigned GET unexpectedly succeeded")
                    status = "expected-failure"
                else:
                    status = "upstream-fixed"
            finally:
                release.set()
                thread.join(30)
                assert not thread.is_alive(), "FileIO initialization did not finish"
            if "error" in worker:
                raise worker["error"]
        traffic = self.entries[start:]
        s3 = [entry for entry in traffic if entry["kind"] == "s3"]
        signing = [
            entry for entry in traffic if entry["kind"] == "rest" and entry["url"].endswith("/sign")
        ]
        if status == "expected-failure":
            assert worker["fs"] is self.fs, "Expected shared filesystem was not reused"
            assert not signing, "Failed operation reached the signer"
            assert [(entry["method"], entry["status"]) for entry in s3] == [
                ("HEAD", 403),
                ("GET", 403),
            ], s3
            assert all("authorization" not in {k.lower() for k in entry["headers"]} for entry in s3)
            assert "<Code>AccessDenied</Code>" in s3[1]["error"]
        else:
            assert s3 and all(entry["status"] in (200, 206) for entry in s3), s3
            assert signing, "Successful read must use remote signing"
        result = {
            "status": status,
            "shared_filesystem": worker["fs"] is self.fs,
            "signer_calls_in_gap": len(signing),
            "s3": [
                {k: entry[k] for k in ("method", "status", "response_headers", "error")}
                for entry in s3
            ],
        }
        self.emit("canary", **result)
        return result

    def after(self):
        results = {}
        try:
            # Same live catalog, table and filesystem; no refresh or new keys.
            self.phase = "after_serial_control"
            results["same_table"] = self.read(self.table)
            self.phase = "after_forced_interleaving"
            results["canary"] = self.race()
            for label, load in (
                ("same_table_recovered", lambda: self.table),
                ("reload_table", lambda: self.catalog.load_table("integration.from_trino")),
                (
                    "new_catalog",
                    lambda: self.factory("remote-signing", False).load_table(
                        "integration.from_trino"
                    ),
                ),
            ):
                self.phase = label
                table = load()

                # Auth manager instances differ, but all server-supplied signing
                # and storage properties must be unchanged across recreation.
                def config(props):
                    return {k: v for k, v in props.items() if k != "auth.manager"}

                assert config(table.io.properties) == config(self.properties)
                self.emit("properties", properties=table.io.properties, same=True)
                results[label] = self.read(table)
            if results["canary"]["status"] == "upstream-fixed":
                notice = "Remote-signing initialization race no longer reproduces; review the pinned client fix and retire T9's expected failure."
                print("::notice title=Remote-signing canary passed::" + notice, flush=True)
                if os.environ.get("GITHUB_STEP_SUMMARY"):
                    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as summary:
                        summary.write("\n**" + notice + "**\n")
            return results
        finally:
            self.stack.close()
