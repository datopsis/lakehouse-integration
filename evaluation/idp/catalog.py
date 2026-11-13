"""Real pinned Lakekeeper behind the owner-approved, unchanged NGINX profile."""

import base64
import hashlib
import json
import os
import socket
import ssl
import subprocess
import time

from common import HTTPS, NETWORK, ROOT, WORK, decode, host, run, save, secret, wait, write

PROXY_REVISION = "9ef9e822c6b5e508cebef2adff3bb647a206773c"
PROXY_IMAGE = "localhost/nginx-ubi:idp-bakeoff"
LABEL = "datopsis.idp-bakeoff=true"
ROWS = [{"id": 1, "label": "alpha"}, {"id": 2, "label": "beta"}]


def build_proxy(arch, owner):
    source = ROOT / ".sources/nginx-ubi"
    source.mkdir()
    run("git", "init", "-q", source)
    run("git", "-C", source, "remote", "add", "origin", "https://github.com/datopsis/nginx-ubi.git")
    run("git", "-C", source, "fetch", "--depth=1", "origin", PROXY_REVISION)
    run("git", "-C", source, "checkout", "--detach", "FETCH_HEAD")
    assert run("git", "-C", source, "rev-parse", "HEAD") == PROXY_REVISION
    env = dict(os.environ, CONTAINER_RUNTIME="podman")
    run(
        "python3",
        "scripts/artifacts.py",
        "acquire",
        "--lock",
        f"artifacts/locks/{arch}.json",
        "--output",
        f".artifact-bundle/{arch}",
        cwd=source,
        env=env,
    )
    run("bash", "scripts/build-image.sh", arch, PROXY_IMAGE, cwd=source, env=env)
    archive = ROOT / ".sources/nginx-transfer.tar"
    run("podman", "save", "--format", "docker-archive", "-o", archive, PROXY_IMAGE)
    run("docker", "load", "-i", archive)
    archive.unlink()
    lock = source / f"artifacts/locks/{arch}.json"
    obj = json.loads(run("docker", "image", "inspect", PROXY_IMAGE))[0]
    lock_hash = hashlib.sha256(lock.read_bytes()).hexdigest()
    errors = owner.provenance_errors(obj, PROXY_REVISION, lock_hash, arch)
    assert not errors, errors
    assert not run("git", "-C", source, "diff", "HEAD")
    profile = source / "examples/profiles/lakekeeper/nginx.conf"
    return {
        "status": "pass",
        "revision": PROXY_REVISION,
        "architecture": arch,
        "lock_sha256": lock_hash,
        "labels": obj["Config"]["Labels"],
        "image_id": obj["Id"],
        "profile_sha256": hashlib.sha256(profile.read_bytes()).hexdigest(),
    }


def stop(name):
    obj = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
    save(name + ".log.json", {"log": obj.stdout + obj.stderr})
    run("docker", "rm", "-fv", name)


class Storage:
    def __init__(self):
        self.access, self.password = secret(), secret()
        self.endpoint = "http://s3.idp.test:8333"

    def start(self):
        config = WORK / "storage/s3.json"
        write(
            config,
            {
                "identities": [
                    {
                        "name": "bakeoff",
                        "credentials": [{"accessKey": self.access, "secretKey": self.password}],
                        "actions": ["Read:warehouse", "Write:warehouse", "List:warehouse"],
                    }
                ]
            },
        )
        run("sudo", "chown", "root:root", config)
        run("sudo", "chmod", "0440", config)
        commands = {
            "master": ["master", "-mdir=/data", "-ip=idp-master", "-volumeSizeLimitMB=64"],
            "volume": [
                "volume",
                "-dir=/data",
                "-ip=idp-volume",
                "-mserver=idp-master:9333",
                "-max=4",
            ],
            "filer": [
                "filer",
                "-ip=idp-filer",
                "-master=idp-master:9333",
                "-defaultStoreDir=/data",
            ],
            "s3": [
                "s3",
                "-filer=idp-filer:8888",
                "-ip.bind=0.0.0.0",
                "-config=/run/secrets/s3.json",
            ],
        }
        for name, command in commands.items():
            args = [
                "docker",
                "run",
                "-d",
                "--name",
                "idp-" + name,
                "--label",
                LABEL,
                "--network",
                NETWORK,
                "--network-alias",
                "idp-" + name,
            ]
            if name == "s3":
                args += [
                    "--network-alias",
                    "s3.idp.test",
                    "-v",
                    f"{config}:/run/secrets/s3.json:ro",
                ]
            run(*args, "localhost/seaweedfs-ubi:integration", *command)
        host("idp-s3", "s3.idp.test")
        wait(
            lambda: (
                "warehouse"
                in run(
                    "docker",
                    "exec",
                    "-i",
                    "idp-master",
                    "weed",
                    "shell",
                    "-master=idp-master:9333",
                    "-filer=idp-filer:8888",
                    input="s3.bucket.create -name warehouse\ns3.bucket.list\n",
                )
            )
        )

    def properties(self):
        return {
            "s3.endpoint": self.endpoint,
            "s3.region": "local",
            "s3.path-style-access": "true",
            "s3.access-key-id": self.access,
            "s3.secret-access-key": self.password,
        }


class Catalog:
    def __init__(self, provider, pg_env, storage):
        self.provider, self.storage = provider, storage
        self.name = provider.name
        self.proxy = "idp-proxy-" + self.name
        self.backend = "idp-catalog-" + self.name
        self.hostname = "catalog-" + self.name + ".idp.test"
        self.base = "https://" + self.hostname + ":8181"
        self.http = HTTPS(provider.ca)
        self.env = WORK / ("catalog-" + self.name + ".env")
        db = "lk_" + self.name
        run(
            "docker",
            "exec",
            "idp-postgres",
            "psql",
            "-X",
            "-h",
            "/tmp",
            "-U",
            "postgres",
            "-d",
            "lakekeeper",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            f"CREATE DATABASE {db} WITH OWNER lakekeeper TEMPLATE lakekeeper",
        )
        write(
            self.env,
            pg_env.read_text().replace("@postgres:5432/lakekeeper", "@postgres:5432/" + db),
        )
        run(
            "docker",
            "run",
            "--rm",
            "--label",
            LABEL,
            "--network",
            NETWORK,
            "--env-file",
            self.env,
            "localhost/lakekeeper-ubi:integration",
            "migrate",
        )

    def start(self):
        tls = WORK / ("catalog-" + self.name) / "tls"
        # Keep the exact upstream profile, including paths and loopback-only backend.
        (tls / "cert.pem").rename(tls / "server.crt")
        (tls / "key.pem").rename(tls / "server.key")
        run("sudo", "chown", "root:root", tls / "server.key")
        run("sudo", "chmod", "0440", tls / "server.key")
        profile = ROOT / ".sources/nginx-ubi/examples/profiles/lakekeeper"
        run(
            "docker",
            "run",
            "-d",
            "--name",
            self.proxy,
            "--label",
            LABEL,
            "--network",
            NETWORK,
            "--network-alias",
            self.hostname,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
            "-v",
            f"{profile}:/etc/nginx/profile:ro",
            "-v",
            f"{tls}:/etc/nginx/tls:ro",
            PROXY_IMAGE,
            "-c",
            "/etc/nginx/profile/nginx.conf",
            "-g",
            "daemon off;",
        )
        self.address = host(self.proxy, self.hostname)
        self.start_backend()
        return self.transport()

    def start_backend(self, audience="lakekeeper"):
        run(
            "docker",
            "run",
            "-d",
            "--name",
            self.backend,
            "--label",
            LABEL,
            "--network",
            "container:" + self.proxy,
            "--env-file",
            self.env,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "-e",
            "LAKEKEEPER__BIND_IP=127.0.0.1",
            "-e",
            "LAKEKEEPER__LISTEN_PORT=8182",
            "-e",
            "LAKEKEEPER__BASE_URI=" + self.base,
            "-e",
            "LAKEKEEPER__OPENID_PROVIDER_URI=" + self.provider.issuer.rstrip("/"),
            "-e",
            "LAKEKEEPER__OPENID_AUDIENCE=" + audience,
            "-e",
            "LAKEKEEPER__OPENID_SUBJECT_CLAIM=sub",
            "-e",
            "LAKEKEEPER__OPENID_ROLES_CLAIM=groups",
            "-e",
            "SSL_CERT_FILE=/ca/ca.pem",
            "-v",
            f"{self.provider.ca}:/ca/ca.pem:ro",
            "localhost/lakekeeper-ubi:integration",
            "serve",
        )
        wait(lambda: self.http.request("GET", self.base + "/catalog/v1/config").status_code == 401)

    def restart_backend(self, audience="lakekeeper"):
        stop(self.backend)
        self.start_backend(audience)

    def transport(self):
        proxy = json.loads(run("docker", "inspect", self.proxy))[0]
        backend = json.loads(run("docker", "inspect", self.backend))[0]
        assert backend["HostConfig"]["NetworkMode"] == "container:" + proxy["Id"]
        pid = str(proxy["State"]["Pid"])
        listeners = run("sudo", "nsenter", "-t", pid, "-n", "ss", "-H", "-lnt")
        assert "127.0.0.1:8182" in listeners, listeners
        for line in listeners.splitlines():
            address = line.split()[3]
            if address.endswith((":8182", ":9000")):
                assert address.startswith("127.0.0.1:"), listeners
        for port in (8182, 9000):
            try:
                with socket.create_connection((self.hostname, port), timeout=3):
                    pass
            except (ConnectionRefusedError, TimeoutError):
                pass
            else:
                raise AssertionError(f"Backend port {port} exposed on bridge")
        errors = {}
        trusted = ssl.create_default_context(cafile=str(self.provider.ca))
        for label, context, hostname in (
            ("untrusted_ca", ssl.create_default_context(), self.hostname),
            ("wrong_hostname", trusted, "wrong.idp.test"),
        ):
            try:
                with socket.create_connection((self.hostname, 8181), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname):
                        pass
            except ssl.SSLCertVerificationError as exc:
                errors[label] = str(exc)
            else:
                raise AssertionError(label + " accepted")
        with socket.create_connection((self.hostname, 8181), timeout=5) as sock:
            sock.sendall(b"GET / HTTP/1.0\r\nHost: catalog\r\n\r\n")
            reply = sock.recv(1024)
        assert reply.startswith(b"HTTP/1.1 400 "), reply
        return {
            "proxy_revision": PROXY_REVISION,
            "url": self.base,
            "shared_namespace": True,
            "listeners": listeners,
            "negative_errors": errors,
            "anonymous_https_status": 401,
            "plaintext_frontend_status": 400,
            "approved_exception": "HTTP only on 127.0.0.1:8182 inside shared network namespace",
        }

    def request(self, token, expected=200):
        url = self.base + "/catalog/v1/config?warehouse=" + self.warehouse
        r = self.http.request("GET", url, headers={"Authorization": "Bearer " + token})
        try:
            body = r.json()
        except ValueError:
            body = r.text
        evidence = {"http_status": r.status_code, "body": body, "url": url}
        assert r.status_code == expected, evidence
        return evidence

    def seed(self, token):
        headers = {"Authorization": "Bearer " + token}
        self.http.json(
            "POST",
            self.base + "/management/v1/bootstrap",
            headers=headers,
            statuses=(204,),
            json={"accept-terms-of-use": True},
        )
        body = self.http.json(
            "POST",
            self.base + "/management/v1/warehouse",
            headers=headers,
            statuses=(200, 201),
            json={
                "warehouse-name": "bakeoff",
                "storage-profile": {
                    "type": "s3",
                    "bucket": "warehouse",
                    "region": "local",
                    "sts-enabled": False,
                    "flavor": "s3-compat",
                    "endpoint": self.storage.endpoint,
                    "path-style-access": True,
                },
                "storage-credential": {
                    "type": "s3",
                    "credential-type": "access-key",
                    "access-key-id": self.storage.access,
                    "secret-access-key": self.storage.password,
                },
            },
        )
        self.warehouse = body["warehouse-id"]
        catalog = self.pyiceberg(token=token)
        catalog.create_namespace("bakeoff")
        import pyarrow as pa

        table = catalog.create_table(
            "bakeoff.sample",
            schema=pa.schema([pa.field("id", pa.int64()), pa.field("label", pa.string())]),
        )
        table.append(pa.Table.from_pylist(ROWS))
        return self.read(catalog)

    def pyiceberg(self, token=None):
        from pyiceberg.catalog.rest import RestCatalog

        properties = {
            "uri": self.base + "/catalog",
            "warehouse": self.warehouse,
            "ssl": {"cabundle": str(self.provider.ca)},
            "header.X-Iceberg-Access-Delegation": "client-managed",
            **self.storage.properties(),
        }
        if token:
            properties["token"] = token
        else:
            properties.update(
                {
                    "credential": "lakekeeper:" + self.provider.client_secret,
                    "oauth2-server-uri": self.provider.discovery["token_endpoint"],
                    "scope": "openid profile",
                }
            )
        return RestCatalog("bakeoff", **properties)

    @staticmethod
    def read(catalog):
        tables = catalog.list_tables("bakeoff")
        assert tables == [("bakeoff", "sample")], tables
        rows = sorted(
            catalog.load_table("bakeoff.sample").scan().to_arrow().to_pylist(),
            key=lambda row: row["id"],
        )
        assert rows == ROWS, rows
        return {"tables": tables, "rows": rows}

    def wrong_audience(self, token):
        self.request(token)
        try:
            self.restart_backend("wrong-audience")
            result = self.request(token, 401)
        finally:
            self.restart_backend()
        self.request(token)
        return {
            **result,
            "method": "Same genuine token/key/issuer; only expected audience changed",
            "token_audience": decode(token)[1]["aud"],
            "expected_audience": "wrong-audience",
            "positive_control_before_and_after": 200,
        }


def b64(value):
    if isinstance(value, dict):
        value = json.dumps(value, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def bad_token(provider, kind):
    header, claims = decode(provider.human_token)
    if kind == "alg_none":
        return secret(b64({**header, "alg": "none"}) + "." + b64(claims) + ".")
    directory = WORK / "forged" / provider.name
    directory.mkdir(parents=True, exist_ok=True)
    key = directory / "key.pem"
    alg = header["alg"]
    assert alg in ("RS256", "ES256"), alg
    options = (
        ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]
        if alg == "RS256"
        else ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]
    )
    run("openssl", "genpkey", *options, "-out", key)
    key.chmod(0o600)
    content = b64(header) + "." + b64(claims)
    signature = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", str(key)],
        input=content.encode(),
        capture_output=True,
        check=True,
    ).stdout
    if alg == "ES256":
        # ASN.1 DER SEQUENCE(INTEGER r, INTEGER s) -> JOSE fixed-width r || s.
        assert signature[0] == 0x30 and signature[1] == len(signature) - 2
        offset, values = 2, []
        for _ in range(2):
            assert signature[offset] == 2
            size = signature[offset + 1]
            values.append(
                int.from_bytes(signature[offset + 2 : offset + 2 + size], "big").to_bytes(32, "big")
            )
            offset += 2 + size
        assert offset == len(signature)
        signature = b"".join(values)
    return secret(content + "." + b64(signature))


def expired(catalog, token):
    header, claims = decode(token)
    # jsonwebtoken's default permitted clock skew is 60 seconds. No token rewriting.
    deadline = claims["exp"] + 61
    while time.time() <= deadline:
        time.sleep(min(10, deadline - time.time() + 1))
    keys = catalog.provider.http.json("GET", catalog.provider.discovery["jwks_uri"])["keys"]
    assert header["kid"] in {key["kid"] for key in keys}, "Expiry token key no longer published"
    result = catalog.request(token, 401)
    fresh = catalog.provider.human()["access_token"]
    catalog.request(fresh)
    return {
        **result,
        "token_exp": claims["exp"],
        "tested_at": time.time(),
        "kid_still_published": True,
        "fresh_token_positive_control": 200,
    }
