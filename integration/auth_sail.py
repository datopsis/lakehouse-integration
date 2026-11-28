"""Per-team provisioner from datopsis-authz slice 4a (Apache-2.0).

Runs only inside T13's disposable Actions fixture; same loopback/socket boundary.
"""

import json

import common
from common import WORK, run, wait, write
from fixture import BACKEND_NETWORK, container, leaf, transport


def launch(catalog, key, team_tokens):
    restricted = [
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--pids-limit=256",
        "--memory=2g",
        "--cpus=2",
    ]
    teams = []
    for name, group in (("a", "lake-readers"), ("b", "no-access")):
        directory = WORK / ("team-" + name)
        directory.mkdir(mode=0o700)
        sockets = directory / "socket"
        sockets.mkdir(mode=0o700)
        run("sudo", "chown", "999:0", sockets)
        token = directory / "token"
        write(token, team_tokens[name])
        run("sudo", "chown", "10001:10001", token)
        run("sudo", "chmod", "0400", token)
        config = directory / "sail.json"
        config.write_text(
            json.dumps(dict(bind="127.0.0.1", port=50052, allow_unauthenticated_remote=False))
        )
        config.chmod(0o444)
        container(
            "sail-" + name,
            "localhost/sail-ubi:integration",
            env={
                "SAIL_CATALOG__LIST": '[{type="iceberg-rest", name="bakeoff", uri="'
                + catalog.base
                + '/catalog", warehouse="bakeoff", bearer_access_token_file="/run/team-token"}]',
                "SSL_CERT_FILE": "/ca/ca.pem",
                "AWS_ACCESS_KEY_ID": catalog.storage.access,
                "AWS_SECRET_ACCESS_KEY": catalog.storage.password,
                "AWS_ENDPOINT": catalog.storage.endpoint,
                "AWS_REGION": "local",
                "AWS_ALLOW_HTTP": "false",
                "AWS_VIRTUAL_HOSTED_STYLE_REQUEST": "false",
                "TOKIO_WORKER_THREADS": "2",
            },
            mounts=[
                (token, "/run/team-token"),
                (config, "/etc/sail/config.json"),
                (catalog.provider.ca, "/ca/ca.pem"),
            ],
            extra=restricted
            + [
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700",
                "--tmpfs",
                "/var/lib/sail:rw,noexec,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700",
            ],
        )
        container(
            "socket-" + name,
            "localhost/authz-serve:s1",
            ["sail-socket"],
            env={"SAIL_SOCKET": "/socket/sail.sock"},
            network="container:sail-" + name,
            extra=restricted + ["--user", "999:0", "-v", f"{sockets}:/socket:rw"],
        )
        teams.append(dict(id=name, group=group, socket="/teams/" + name + "/sail.sock"))

        def socket_ready():
            run("sudo", "test", "-S", sockets / "sail.sock")
            return True

        wait(socket_ready)
        wait(
            lambda: run(
                "docker",
                "exec",
                "sail-" + name,
                "/usr/bin/python3.12",
                "-c",
                "import socket; socket.create_connection(('127.0.0.1',50052),timeout=1).close(); print('ready')",
            )
        )
    config = WORK / "teams.json"
    config.write_text(json.dumps(teams))
    config.chmod(0o444)
    container(
        "gateway",
        "localhost/authz-serve:s1",
        ["sail-gateway"],
        env={
            "AUTHZ_TLS_CERT": "/tls/cert.pem",
            "AUTHZ_TLS_KEY": "/tls/key.pem",
            "AUTHZ_KEY_FILE": "/run/cedar-key",
            "AUTHZ_CA_FILE": "/ca/ca.pem",
            "AUTHZ_ENDPOINT": "https://cedar:8443",
            "AUTHZ_DATABASE_URL_FILE": "/run/cedar-db-url",
            "AUTHZ_DATABASE_CA_FILE": "/ca/ca.pem",
            "SAIL_TEAMS_FILE": "/teams.json",
            "SAIL_JWKS_URL": catalog.provider.discovery["jwks_uri"],
            "SAIL_ISSUER": catalog.provider.issuer,
            "SAIL_AUDIENCE": "lakekeeper,expiry",
            "AUTHZ_LISTEN": "0.0.0.0:50051",
        },
        mounts=[
            (leaf("sail"), "/tls"),
            (catalog.provider.ca, "/ca/ca.pem"),
            (WORK / "cedar-key", "/run/cedar-key"),
            (WORK / "cedar-db-url", "/run/cedar-db-url"),
            (config, "/teams.json"),
            (WORK / "team-a/socket", "/teams/a"),
            (WORK / "team-b/socket", "/teams/b"),
        ],
        network=BACKEND_NETWORK,
        extra=restricted + ["--user", "999:0"],
    )
    # The audit database must resolve at process startup. Attach the public
    # client/IdP network afterwards; no request is sent before both are ready.
    run("docker", "network", "connect", "--alias", "sail", common.NETWORK, "gateway")
    from common import host

    host("gateway", "sail")
    wait(lambda: transport("sail", 50051, catalog.provider.ca))
