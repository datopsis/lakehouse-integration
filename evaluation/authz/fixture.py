"""Disposable TLS fixture reusing only IdP provisioning and provenance helpers."""

import json
import os
import socket
import ssl
import subprocess
import time

from catalog import LABEL, ROWS, Catalog
from common import HTTPS, NETWORK, ROOT, WORK, host, pki, run, secret, wait, write
from providers import Provider

INPUTS = json.loads((ROOT / "evaluation/authz/inputs.json").read_text())


def leaf(name):
    dest = WORK / name / "tls"
    dest.mkdir(parents=True, exist_ok=True)
    run(
        "openssl",
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        f"/CN={name}",
        "-keyout",
        dest / "key.pem",
        "-out",
        dest / "request.pem",
    )
    ext = dest / "extensions"
    ext.write_text(f"subjectAltName=DNS:{name}\nextendedKeyUsage=serverAuth,clientAuth\n")
    run(
        "openssl",
        "x509",
        "-req",
        "-in",
        dest / "request.pem",
        "-CA",
        WORK / "ca/ca.pem",
        "-CAkey",
        WORK / "ca/key.pem",
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        ext,
        "-out",
        dest / "cert.pem",
    )
    run("sudo", "chown", "root:root", dest / "key.pem")
    run("sudo", "chmod", "0440", dest / "key.pem")
    (dest / "cert.pem").chmod(0o644)
    return dest


def container(name, image, command=(), env=None, mounts=(), extra=(), network=NETWORK):
    args = ["docker", "run", "-d", "--name", name, "--label", LABEL, "--network", network]
    if network == NETWORK:
        args += ["--network-alias", name]
    if env:
        path = WORK / (name + ".env")
        write(path, "".join(f"{k}={v}\n" for k, v in env.items()))
        args += ["--env-file", path]
    for src, dst in mounts:
        args += ["-v", f"{src}:{dst}:ro"]
    run(*args, *extra, image, *command)
    if network == NETWORK:
        host(name, name)


def transport(name, port, ca, client=None):
    ctx = ssl.create_default_context(cafile=str(ca))
    if client:
        ctx.load_cert_chain(*map(str, client))
    with socket.create_connection((name, port), timeout=5) as sock:
        with ctx.wrap_socket(sock, server_hostname=name) as tls:
            version = tls.version()
    for context, hostname in ((ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), name), (ctx, "wrong.test")):
        try:
            with socket.create_connection((name, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname):
                    pass
        except ssl.SSLCertVerificationError:
            pass
        else:
            raise AssertionError("TLS accepted untrusted CA or wrong name")
    with socket.create_connection((name, port), timeout=5) as sock:
        sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        try:
            reply = sock.recv(1024)
        except ConnectionResetError:
            reply = b""
    assert not reply or reply.startswith((b"HTTP/1.1 400", b"\x15\x03")), reply
    return {
        "version": version,
        "unknown_ca_rejected": True,
        "wrong_name_rejected": True,
        "plaintext_rejected": True,
    }


class Rauthy(Provider):
    def config_rauthy(self):
        env, command, mounts = super().config_rauthy()
        clients = self.path / "bootstrap/clients.json"
        data = json.loads(clients.read_text())
        # Distinct bootstrap operator and least-privilege machine subject.
        data.append({**data[0], "id": "operator", "name": "operator"})
        for client in data:
            client["access_token_lifetime"] = 1800
        write(clients, data)
        return env, command, mounts

    def token(self, client="lakekeeper"):
        response = self.http.json(
            "POST",
            self.discovery["token_endpoint"],
            data={
                "grant_type": "client_credentials",
                "client_id": client,
                "client_secret": self.client_secret,
                "scope": "openid profile groups",
            },
        )
        return secret(response["access_token"])


def database(ca):
    tls = leaf("postgres")
    directory = WORK / "postgres"
    directory.mkdir(exist_ok=True)
    admin, password = secret(), secret()
    write(directory / "postgres-password", admin)
    write(directory / "lakekeeper-password", password)
    run(
        "sudo",
        "chown",
        "root:root",
        directory / "postgres-password",
        directory / "lakekeeper-password",
    )
    run("sudo", "chmod", "0440", directory / "postgres-password", directory / "lakekeeper-password")
    container(
        "idp-postgres",
        "localhost/postgresql-lakekeeper-ubi:integration",
        env={
            "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
            "POSTGRES_DB": "lakekeeper",
            "POSTGRESQL_TLS_CERT_FILE": "/tls/cert.pem",
            "POSTGRESQL_TLS_KEY_FILE": "/tls/key.pem",
        },
        mounts=[(directory, "/run/secrets"), (tls, "/tls"), (ca, "/ca/ca.pem")],
        extra=["--network-alias", "postgres"],
    )
    host("idp-postgres", "postgres")
    wait(
        lambda: (
            subprocess.run(
                ["docker", "exec", "idp-postgres", "pg_isready", "-h", "/tmp"], capture_output=True
            ).returncode
            == 0
        )
    )
    run(
        "docker",
        "exec",
        "-i",
        "idp-postgres",
        "psql",
        "-X",
        "-h",
        "/tmp",
        "-U",
        "postgres",
        "-d",
        "lakekeeper",
        input=(ROOT / "integration/postgres-init.sql").read_text(),
    )
    fga_password = secret()
    # SQL enters stdin only; all values are generated hex, and output is redacted.
    run(
        "docker",
        "exec",
        "-i",
        "idp-postgres",
        "psql",
        "-X",
        "-h",
        "/tmp",
        "-U",
        "postgres",
        "-v",
        "ON_ERROR_STOP=1",
        "-d",
        "lakekeeper",
        input=f"CREATE ROLE openfga LOGIN PASSWORD '{fga_password}';\nCREATE DATABASE openfga OWNER openfga;\n",
    )
    url = f"postgres://lakekeeper:{password}@postgres:5432/lakekeeper?sslmode=verify-full&sslrootcert=/ca/ca.pem"
    env = {
        "LAKEKEEPER__PG_DATABASE_URL_WRITE": url,
        "LAKEKEEPER__PG_ENCRYPTION_KEY": secret(),
        "SSL_CERT_FILE": "/ca/ca.pem",
    }
    return (
        env,
        f"postgres://openfga:{fga_password}@postgres:5432/openfga?sslmode=verify-full&sslrootcert=/ca/ca.pem",
    )


def openfga(ca, db, arch):
    image = INPUTS["openfga"]["image"]
    run("docker", "pull", "--platform", "linux/" + arch, image)
    obj = json.loads(run("docker", "image", "inspect", image))[0]
    assert obj["Architecture"] == arch
    tls = leaf("openfga")
    # Upstream nonroot UID can read a group-root key without changing the image.
    key = secret()
    env = {
        "OPENFGA_DATASTORE_ENGINE": "postgres",
        "OPENFGA_DATASTORE_URI": db,
        "OPENFGA_AUTHN_METHOD": "preshared",
        "OPENFGA_AUTHN_PRESHARED_KEYS": key,
        "OPENFGA_GRPC_ADDR": "openfga:8081",
        "OPENFGA_GRPC_TLS_ENABLED": "true",
        "OPENFGA_GRPC_TLS_CERT": "/tls/cert.pem",
        "OPENFGA_GRPC_TLS_KEY": "/tls/key.pem",
        "OPENFGA_HTTP_TLS_ENABLED": "true",
        "OPENFGA_HTTP_TLS_CERT": "/tls/cert.pem",
        "OPENFGA_HTTP_TLS_KEY": "/tls/key.pem",
        "OPENFGA_PLAYGROUND_ENABLED": "false",
        "OPENFGA_METRICS_ENABLED": "false",
    }
    mounts = [(tls, "/tls"), (ca, "/ca/ca.pem")]
    path = WORK / "fga-migration.env"
    write(path, "".join(f"{k}={v}\n" for k, v in env.items()))
    run(
        "docker",
        "run",
        "--rm",
        "--label",
        LABEL,
        "--network",
        NETWORK,
        "--env-file",
        path,
        "-v",
        f"{ca}:/ca/ca.pem:ro",
        image,
        "migrate",
    )
    started = time.monotonic()
    container("openfga", image, ["run"], env, mounts, extra=["--group-add", "0"])
    http = HTTPS(ca)
    headers = {"Authorization": "Bearer " + key}
    wait(
        lambda: (
            http.request("GET", "https://openfga:8080/stores", headers=headers).status_code == 200
        )
    )
    return key, {
        "startup_seconds": time.monotonic() - started,
        "image_bytes": obj["Size"],
        "image_id": obj["Id"],
        "http_tls": transport("openfga", 8080, ca),
        "grpc_tls": transport("openfga", 8081, ca),
    }


class Storage:
    def __init__(self, ca):
        self.ca = ca
        self.access, self.password = secret(), secret()
        self.endpoint = "https://s3:8333"

    def start(self):
        # Native verified HTTP and mTLS gRPC on every Seaweed inter-service path.
        config = WORK / "storage/s3.json"
        write(
            config,
            {
                "identities": [
                    {
                        "name": "fixture",
                        "credentials": [{"accessKey": self.access, "secretKey": self.password}],
                        "actions": ["Admin", "Read", "Write", "List"],
                    }
                ]
            },
        )
        run("sudo", "chown", "root:root", config)
        run("sudo", "chmod", "0440", config)
        for name in ("master", "volume", "filer", "s3"):
            tls = leaf(name)
            security = WORK / name / "security.toml"
            text = '[grpc]\nca="/ca/ca.pem"\nallowed_server_commonNames="master,volume,filer,s3"\n'
            for service in ("master", "volume", "filer", "s3", "client"):
                text += f'[grpc.{service}]\ncert="/tls/cert.pem"\nkey="/tls/key.pem"\n'
            text += '[https.client]\nenabled=true\nca="/ca/ca.pem"\ncert="/tls/cert.pem"\nkey="/tls/key.pem"\ninsecure_skip_verify=false\n'
            for service in ("master", "volume", "filer"):
                text += f'[https.{service}]\ncert="/tls/cert.pem"\nkey="/tls/key.pem"\n'
            write(security, text)
            security.chmod(0o644)
            commands = {
                "master": ["master", "-mdir=/data", "-ip=master", "-volumeSizeLimitMB=64"],
                "volume": ["volume", "-dir=/data", "-ip=volume", "-mserver=master:9333", "-max=4"],
                "filer": ["filer", "-ip=filer", "-master=master:9333", "-defaultStoreDir=/data"],
                "s3": [
                    "s3",
                    "-filer=filer:8888",
                    "-ip.bind=0.0.0.0",
                    "-config=/secrets/s3.json",
                    "-iam.readOnly=false",
                    "-cert.file=/tls/cert.pem",
                    "-key.file=/tls/key.pem",
                ],
            }
            container(
                name,
                "localhost/seaweedfs-ubi:integration",
                commands[name],
                mounts=[
                    (tls, "/tls"),
                    (self.ca, "/ca/ca.pem"),
                    (security, "/etc/seaweedfs/security.toml"),
                    (config, "/secrets/s3.json"),
                ],
            )
        import botocore.session

        self.s3 = botocore.session.get_session().create_client(
            "s3",
            endpoint_url=self.endpoint,
            region_name="local",
            aws_access_key_id=self.access,
            aws_secret_access_key=self.password,
            verify=str(self.ca),
        )
        wait(lambda: self.s3.list_buckets())
        self.s3.create_bucket(Bucket="warehouse")
        return {
            name: transport(name, port, self.ca)
            for name, port in (("master", 9333), ("volume", 8080), ("filer", 8888), ("s3", 8333))
        }

    def properties(self):
        return {
            "s3.endpoint": self.endpoint,
            "s3.region": "local",
            "s3.path-style-access": "true",
            "s3.access-key-id": self.access,
            "s3.secret-access-key": self.password,
            "py-io-impl": "pyiceberg.io.fsspec.FsspecFileIO",
        }


class AuthCatalog(Catalog):
    def __init__(self, provider, env, storage):
        # Use a dedicated DB in this run, never the main fixture database.
        self.provider, self.storage = provider, storage
        self.name = "rauthy"
        self.proxy, self.backend = "idp-proxy-rauthy", "idp-catalog-rauthy"
        self.hostname = "catalog-rauthy.idp.test"
        self.base = "https://" + self.hostname + ":8181"
        self.http = HTTPS(provider.ca)
        self.env = WORK / "catalog.env"
        write(self.env, "".join(f"{k}={v}\n" for k, v in env.items()))
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
            "-v",
            f"{provider.ca}:/ca/ca.pem:ro",
            "localhost/lakekeeper-ubi:integration",
            "migrate",
        )

    def start_backend(self, audience="lakekeeper,operator"):
        return super().start_backend(audience)

    def seed(self, token):
        headers = {"Authorization": "Bearer " + token}
        self.http.json(
            "POST",
            self.base + "/management/v1/bootstrap",
            headers=headers,
            statuses=(204,),
            json={"accept-terms-of-use": True, "is-operator": True},
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
        self.warehouse_id, self.warehouse = body["warehouse-id"], "bakeoff"
        catalog = self.pyiceberg(token)
        import pyarrow as pa

        for namespace in ("bakeoff", "denied"):
            catalog.create_namespace(namespace)
            table = catalog.create_table(
                namespace + ".sample",
                schema=pa.schema([pa.field("id", pa.int64()), pa.field("label", pa.string())]),
            )
            table.append(pa.Table.from_pylist(ROWS))
        return self.read(catalog)


def setup(arch, record):
    ca = pki()
    os.environ["AWS_CA_BUNDLE"] = str(ca)
    run("docker", "network", "create", "--internal", NETWORK)
    provider = Rauthy("rauthy", ca)
    record("rauthy", lambda: provider.start(arch), required=True)
    env, fga_db = database(ca)
    key, info = openfga(ca, fga_db, arch)
    record("openfga_startup_tls", lambda: info)
    env.update(
        {
            "LAKEKEEPER__AUTHZ_BACKEND": "openfga",
            "LAKEKEEPER__OPENFGA__ENDPOINT": "https://openfga:8081",
            "LAKEKEEPER__OPENFGA__API_KEY": key,
            "LAKEKEEPER__DEFAULT_PROJECT_ID": "00000000-0000-0000-0000-000000000000",
        }
    )
    storage = Storage(ca)
    record("storage_tls", storage.start, required=True)
    catalog = AuthCatalog(provider, env, storage)
    record("lakekeeper_tls", catalog.start, required=True)
    operator = provider.token("operator")
    record("seed", lambda: catalog.seed(operator), required=True)
    return catalog, operator, key
