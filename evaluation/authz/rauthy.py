"""Hardened Rauthy profile: owner launcher, PostgreSQL and verified TLS."""

import base64
import json
import os
import time

from common import ROOT, decode, host, run, secret, wait, write
from providers import Provider

REVISION = "1e114b84b01988bf15306b110b040378878488d3"
IMAGE = "localhost/rauthy-ubi:authz"


def build(arch, owner):
    source = ROOT / ".sources/rauthy-ubi"
    source.mkdir()
    run("git", "init", "-q", source)
    run(
        "git", "-C", source, "remote", "add", "origin", "https://github.com/datopsis/rauthy-ubi.git"
    )
    run("git", "-C", source, "fetch", "--depth=1", "origin", REVISION)
    run("git", "-C", source, "checkout", "--detach", "FETCH_HEAD")
    assert run("git", "-C", source, "rev-parse", "HEAD") == REVISION
    run("bash", "scripts/build.sh", cwd=source, env=dict(os.environ, TEST_IMAGE=IMAGE))
    obj = json.loads(run("docker", "image", "inspect", IMAGE))[0]
    lock = source / f"artifacts/locks/{arch}.json"
    errors = owner.provenance_errors(obj, REVISION, owner.sha(lock), arch)
    assert not errors, errors
    assert not run("git", "-C", source, "diff", "HEAD")
    return {
        "status": "pass",
        "revision": REVISION,
        "lock_sha256": owner.sha(lock),
        "architecture": obj["Architecture"],
        "labels": obj["Config"]["Labels"],
    }


class Rauthy(Provider):
    def start(self, arch):
        from fixture import container, leaf

        assert json.loads(run("docker", "image", "inspect", IMAGE))[0]["Architecture"] == arch
        self.config_rauthy()
        clients_path = self.path / "bootstrap/clients.json"
        clients = json.loads(clients_path.read_text())
        clients += [
            {**clients[0], "id": "operator", "name": "operator"},
            {**clients[0], "id": "expiry", "name": "expiry"},
        ]
        for client in clients:
            client["access_token_lifetime"] = 30 if client["id"] == "expiry" else 1800
        write(clients_path, clients)
        api_keys = self.path / "bootstrap/api_keys.json"
        keys = json.loads(api_keys.read_text())
        keys[0]["access"] += [{"group": "Users", "access_rights": ["read", "update"]}]
        write(api_keys, keys)
        pg_password = secret()
        run(
            "docker",
            "exec",
            "-i",
            "idp-postgres",
            "psql",
            "-h",
            "/tmp",
            "-U",
            "postgres",
            "-v",
            "ON_ERROR_STOP=1",
            input=f"CREATE ROLE rauthy LOGIN PASSWORD '{pg_password}';\nCREATE DATABASE rauthy OWNER rauthy;\n",
        )
        tls = self.path / "tls"
        cluster = leaf("localhost")
        secrets = self.path / "secrets"
        values = {
            "server.crt": (tls / "cert.pem").read_text(),
            "server.key": (tls / "key.pem").read_text(),
            "cluster.crt": (cluster / "cert.pem").read_text(),
            "cluster.key": run("sudo", "cat", cluster / "key.pem"),
            "ca.crt": self.ca.read_text(),
            "pg-ca.crt": self.ca.read_text(),
            "pg-password": pg_password,
            "raft-secret": secret(),
            "api-secret": secret(),
            "encryption-keys": "ci/" + secret(base64.b64encode(os.urandom(32)).decode()),
            "encryption-key-active": "ci",
            "admin-password-argon2id": run(
                "argon2", secret(), "-id", "-e", input=self.admin_secret
            ),
        }
        for name, value in values.items():
            write(secrets / name, value)
        data = self.path / "data"
        data.mkdir()
        run("sudo", "chown", "-R", "10001:10001", self.path)
        container(
            self.container,
            IMAGE,
            env={
                "PUB_URL": self.hostname + ":8443",
                "RP_ID": self.hostname,
                "RP_ORIGIN": self.base,
                "PG_HOST": "postgres",
                "PG_USER": "rauthy",
                "PG_DB_NAME": "rauthy",
                "BOOTSTRAP_ADMIN_EMAIL": "admin@idp.test",
            },
            mounts=[(secrets, "/run/secrets"), (self.path / "bootstrap", "/bootstrap")],
            extra=[
                "--network-alias",
                self.hostname,
                "-v",
                f"{data}:/data:rw",
                "--read-only",
                "--cap-drop=ALL",
                "--security-opt=no-new-privileges:true",
                "--memory=2g",
                "--cpus=2",
                "--tmpfs",
                "/tmp:uid=10001,gid=10001,size=64m",
            ],
        )
        host(self.container, self.hostname)
        wait(
            lambda: self.http.request("GET", self.base + "/auth/v1/health").status_code == 200, 180
        )
        self.provision_rauthy()
        self.discovery = self.http.json(
            "GET", self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        )
        assert self.discovery["issuer"] == self.issuer
        return {"image": IMAGE, "revision": REVISION, "discovery": self.discovery}

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
        token = secret(response["access_token"])
        assert decode(token)[1]["exp"] > time.time()
        return token

    def remove_group(self, subject):
        url = self.base + "/auth/v1/users/" + subject
        user = self.http.json("GET", url, headers=self.admin)
        user["groups"] = []
        self.http.json("PUT", url, headers=self.admin, statuses=(200, 202), json=user)
        return self.http.json("GET", url, headers=self.admin)
