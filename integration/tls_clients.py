"""One real client operation per fresh process, for the TLS negative matrix.

Every mode uses the run CA with full verification (hostname included); none can
disable verification. The parent decides which name resolves to the mutation
relay. Prints exactly one CLIENT_RESULT line and always exits 0, so the parent
classifies the actual outcome and error text.
"""

import json
import os
import sys
import traceback
import urllib.error
import urllib.request

CA = os.environ["SSL_CERT_FILE"]


def urllib_get(url):
    import ssl

    context = ssl.create_default_context(cafile=CA)
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )
    with opener.open(url, timeout=20) as response:
        return response.status


def catalog():
    from pyiceberg.catalog.rest import RestCatalog

    return RestCatalog(
        "qualification",
        **{
            "uri": "https://catalog:8181/catalog",
            "ssl": {"cabundle": CA},
            "warehouse": "qualification",
            "s3.endpoint": "https://s3:8333",
            "s3.region": "local",
            "s3.path-style-access": "true",
            "s3.access-key-id": os.environ["PROBE_ACCESS"],
            "s3.secret-access-key": os.environ["PROBE_SECRET"],
            "s3.connect-timeout": "10",
            "s3.request-timeout": "20",
        },
    )


def run(mode, argument):
    if mode == "urllib":
        return urllib_get(argument)
    if mode == "pyiceberg":
        return str(catalog().load_table("integration.from_trino").metadata_location)
    if mode == "pyarrow":
        rows = catalog().load_table("integration.from_trino").scan().to_arrow()
        return rows.sort_by("id").to_pylist()
    if mode == "botocore":
        import botocore.session
        from botocore.config import Config

        client = botocore.session.get_session().create_client(
            "s3",
            endpoint_url="https://s3:8333",
            region_name="local",
            verify=CA,
            aws_access_key_id=os.environ["PROBE_ACCESS"],
            aws_secret_access_key=os.environ["PROBE_SECRET"],
            config=Config(
                s3={"addressing_style": "path"},
                retries={"max_attempts": 0},
                connect_timeout=5,
                read_timeout=15,
            ),
        )
        return client.list_objects_v2(Bucket="warehouse", MaxKeys=1)["KeyCount"]
    if mode == "spark":
        # Runs in Sail's isolated venv; the pinned retry policy never retries
        # certificate failures (it matches only the documented stream reset).
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from sail_client import session

        spark = session(argument)
        try:
            query = os.environ["PROBE_QUERY"]
            return [list(row) for row in spark.sql(query).collect()]
        finally:
            spark.stop()
    if mode == "lakekeeper-loopback":
        # Inside the probe catalog's own network namespace only: the backend
        # listens on 127.0.0.1 and this request never crosses a network.
        payload = json.loads(os.environ["PROBE_PAYLOAD"])
        request = urllib.request.Request(
            "http://127.0.0.1:8182/management/v1/warehouse",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(request, timeout=90) as response:
                body = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"HTTP {exc.code}: {exc.read().decode()[:2000]}") from None
        warehouse = body["warehouse-id"]
        delete = urllib.request.Request(
            f"http://127.0.0.1:8182/management/v1/warehouse/{warehouse}", method="DELETE"
        )
        with opener.open(delete, timeout=30) as response:
            assert response.status in (200, 204), response.status
        return "created and deleted " + warehouse
    raise ValueError(mode)


def main():
    mode, argument = sys.argv[1], (sys.argv[2] if len(sys.argv) > 2 else "")
    try:
        result = {"ok": True, "value": run(mode, argument)}
    except Exception as exc:
        result = {
            "ok": False,
            "type": type(exc).__module__ + "." + type(exc).__name__,
            "error": (str(exc) + "\n" + traceback.format_exc())[-6000:],
        }
    print("CLIENT_RESULT=" + json.dumps(result, default=str), flush=True)


if __name__ == "__main__":
    main()
