"""Official upstream images only; release and OCI index resolved 2026-11-13.

These evaluation-only references never feed integration/build.py or images.lock.json.
"""

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit

from common import HTTPS, WORK, challenge, decode, host, run, secret, wait, write

IMAGES = {
    "keycloak": "quay.io/keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0",
    "rauthy": "ghcr.io/sebadob/rauthy@sha256:d733b7580f53c1601c286b5504853b2774e70245f5f9427d9bcda32496b753ee",
    "kanidm": "docker.io/kanidm/server@sha256:71b6ff5a9c9c32b632894d8acef5a2afc77941b35a0aa95dcee959fe688d5ce9",
}
VERSIONS = {"keycloak": "26.8.2", "rauthy": "0.37.2", "kanidm": "1.12.0"}
CALLBACK = "https://client.idp.test/callback"
SCOPE = "openid profile groups"


class Form(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.action = None
        self.fields = {}
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form" and attrs.get("id") == "kc-form-login":
            self.action = attrs["action"]
        if tag == "input" and attrs.get("name") and attrs.get("type") == "hidden":
            self.fields[attrs["name"]] = attrs.get("value", "")


class Provider:
    def __init__(self, name, ca):
        self.name = name
        self.path = WORK / name
        self.hostname = name + ".idp.test"
        self.base = f"https://{self.hostname}:8443"
        self.issuer = (
            self.base
            + {
                "keycloak": "/realms/bakeoff",
                "rauthy": "/auth/v1/",
                "kanidm": "/oauth2/openid/lakekeeper",
            }[name]
        )
        self.http = HTTPS(ca)
        self.password = secret()
        self.client_secret = secret()
        self.admin_secret = secret()
        self.container = "idp-" + name
        self.ca = ca
        self.admin = None

    def start(self, arch):
        image = IMAGES[self.name]
        run("docker", "pull", "--platform", "linux/" + arch, image)
        obj = json.loads(run("docker", "image", "inspect", image))[0]
        assert obj["Architecture"] == arch, obj["Architecture"]
        data = self.path / "data"
        data.mkdir()
        env, command, mounts = getattr(self, "config_" + self.name)()
        # Docker CLI reads this as the runner; only mounted files change owner.
        envfile = WORK / (self.name + ".env")
        write(envfile, "".join(f"{k}={v}\n" for k, v in env.items()))
        uid = {"keycloak": "1000:0", "rauthy": "10001:10001", "kanidm": "0:0"}[self.name]
        run("sudo", "chown", "-R", uid, self.path)
        args = [
            "docker",
            "create",
            "--name",
            self.container,
            "--label",
            "datopsis.idp-bakeoff=true",
            "--network",
            "idp-bakeoff",
            "--network-alias",
            self.hostname,
            "--env-file",
            envfile,
            "--cpus",
            "2",
            "--memory",
            "2g",
        ]
        for src, dst, mode in [(self.path / "tls", "/tls", "ro"), *mounts]:
            args += ["-v", f"{src}:{dst}:{mode}"]
        run(*args, image, *command)
        self.started = time.monotonic()
        run("docker", "start", self.container)
        host(self.container, self.hostname)
        readiness = self.base + (
            "/status"
            if self.name == "kanidm"
            else (
                "/realms/master/.well-known/openid-configuration"
                if self.name == "keycloak"
                else "/auth/v1/health"
            )
        )
        wait(lambda: self.http.request("GET", readiness).status_code == 200, 180)
        self.startup_seconds = round(time.monotonic() - self.started, 3)
        getattr(self, "provision_" + self.name)()
        self.discovery = self.http.json(
            "GET", self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        )
        assert self.discovery["issuer"] == self.issuer, self.discovery
        for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
            assert urlsplit(self.discovery[key]).scheme == "https", self.discovery
        return {
            "image": image,
            "image_id": obj["Id"],
            "architecture": obj["Architecture"],
            "version": VERSIONS[self.name],
            "startup_seconds": self.startup_seconds,
            "discovery": self.discovery,
            "image_bytes": obj["Size"],
        }

    def config_keycloak(self):
        clients = []
        for name in ("lakekeeper", "wrong-audience"):
            clients.append(
                {
                    "clientId": name,
                    "secret": self.client_secret,
                    "enabled": True,
                    "publicClient": False,
                    "serviceAccountsEnabled": True,
                    "standardFlowEnabled": True,
                    "redirectUris": [CALLBACK],
                    "defaultClientScopes": ["basic", "profile", "email"],
                    "attributes": {"pkce.code.challenge.method": "S256"},
                    "protocolMappers": [
                        {
                            "name": "audience",
                            "protocol": "openid-connect",
                            "protocolMapper": "oidc-audience-mapper",
                            "config": {
                                "included.custom.audience": name,
                                "access.token.claim": "true",
                            },
                        },
                        {
                            "name": "groups",
                            "protocol": "openid-connect",
                            "protocolMapper": "oidc-group-membership-mapper",
                            "config": {
                                "claim.name": "groups",
                                "full.path": "false",
                                "access.token.claim": "true",
                                "id.token.claim": "true",
                            },
                        },
                    ],
                }
            )
        realm = {
            "realm": "bakeoff",
            "enabled": True,
            "sslRequired": "all",
            "clients": clients,
            "groups": [{"name": "lake-readers"}],
            "users": [
                {
                    "username": "alice",
                    "enabled": True,
                    "emailVerified": True,
                    "email": "alice@idp.test",
                    "firstName": "Alice",
                    "lastName": "Test",
                    "groups": ["lake-readers"],
                    "credentials": [
                        {"type": "password", "value": self.password, "temporary": False}
                    ],
                }
            ],
        }
        write(self.path / "realm/bakeoff-realm.json", realm)
        return (
            {
                "KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
                "KC_BOOTSTRAP_ADMIN_PASSWORD": self.admin_secret,
                # Narayana otherwise reserves a plaintext loopback socket as a PID.
                # Use its upstream JVM PID implementation in this single-node fixture.
                "JAVA_OPTS_APPEND": "-Dcom.arjuna.ats.internal.arjuna.utils.processImplementation="
                "com.arjuna.ats.internal.arjuna.utils.MBeanProcessId",
            },
            [
                "start",
                "--http-enabled=false",
                "--https-port=8443",
                "--https-certificate-file=/tls/cert.pem",
                "--https-certificate-key-file=/tls/key.pem",
                "--hostname=" + self.base,
                "--db=dev-file",
                "--cache=local",
                "--import-realm",
            ],
            [
                (self.path / "realm", "/opt/keycloak/data/import", "ro"),
                (self.path / "data", "/opt/keycloak/data/h2", "rw"),
            ],
        )

    def provision_keycloak(self):
        token = self.http.json(
            "POST",
            self.base + "/realms/master/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "admin",
                "password": self.admin_secret,
            },
        )
        self.admin = {"Authorization": "Bearer " + secret(token["access_token"])}

    def config_rauthy(self):
        bootstrap = self.path / "bootstrap"
        write(bootstrap / "groups.json", [{"name": "lake-readers"}])
        write(
            bootstrap / "users.json",
            [
                {
                    "email": "alice@idp.test",
                    "given_name": "Alice",
                    "family_name": "Test",
                    "password": {"Plain": self.password},
                    "groups": ["lake-readers"],
                    "roles": ["user"],
                    "enabled": True,
                    "email_verified": True,
                }
            ],
        )
        write(
            bootstrap / "api_keys.json",
            [
                {
                    "name": "bakeoff",
                    "secret": {"Plain": self.admin_secret},
                    "access": [{"group": "Secrets", "access_rights": ["read", "update"]}],
                }
            ],
        )
        write(
            bootstrap / "clients.json",
            [
                {
                    "id": name,
                    "name": name,
                    "secret": {"Plain": self.client_secret},
                    "redirect_uris": [CALLBACK],
                    "enabled": True,
                    "flows_enabled": ["authorization_code", "client_credentials"],
                    "access_token_alg": "RS256",
                    "id_token_alg": "RS256",
                    "auth_code_lifetime": 60,
                    "access_token_lifetime": 120,
                    "scopes": SCOPE.split(),
                    "default_scopes": SCOPE.split(),
                    "challenges": ["S256"],
                    "force_mfa": False,
                }
                for name in ("lakekeeper", "wrong-audience")
            ],
        )
        key = secret(base64.b64encode(secrets.token_bytes(32)).decode())
        return (
            {
                "PUB_URL": self.hostname + ":8443",
                "LISTEN_SCHEME": "https",
                "LISTEN_PORT_HTTPS": "8443",
                "CLIENT_CREDENTIALS_MAP_SUB": "true",
                "TLS_CERT": "/tls/cert.pem",
                "TLS_KEY": "/tls/key.pem",
                "HQL_NODE_ID": "1",
                "HQL_NODES": f"1 {self.hostname}:8100 {self.hostname}:8200",
                "HQL_TLS_RAFT_CERT": "/tls/cert.pem",
                "HQL_TLS_RAFT_KEY": "/tls/key.pem",
                "HQL_TLS_API_CERT": "/tls/cert.pem",
                "HQL_TLS_API_KEY": "/tls/key.pem",
                "SSL_CERT_FILE": "/ca/ca.pem",
                "HQL_SECRET_RAFT": secret(),
                "HQL_SECRET_API": secret(),
                "ENC_KEYS": "ci/" + key,
                "ENC_KEY_ACTIVE": "ci",
                "BOOTSTRAP_ADMIN_EMAIL": "admin@idp.test",
                "BOOTSTRAP_ADMIN_PASSWORD_PLAIN": self.admin_secret,
                "BOOTSTRAP_DIR": "/bootstrap",
                "RP_ID": self.hostname,
                "RP_ORIGIN": self.base,
            },
            ["serve"],
            [
                (bootstrap, "/bootstrap", "ro"),
                (self.path / "data", "/app/data", "rw"),
                (self.ca, "/ca/ca.pem", "ro"),
            ],
        )

    def provision_rauthy(self):
        self.admin = {"Authorization": "API-Key bakeoff$" + self.admin_secret}

    def config_kanidm(self):
        write(
            self.path / "data/server.toml",
            'version = "2"\nbindaddress = "0.0.0.0:8443"\n'
            'db_path = "/data/kanidm.db"\ntls_chain = "/tls/cert.pem"\ntls_key = "/tls/key.pem"\n'
            f'domain = "{self.hostname}"\norigin = "{self.base}"\n',
        )
        return ({}, [], [(self.path / "data", "/data", "rw")])

    def kanidm_login(self, username, password):
        http = HTTPS(self.ca)
        headers = {}
        steps = [{"init2": {"username": username, "issue": "token", "privileged": True}}]
        if username == "alice":
            steps += [{"begin": "passwordmfa"}, {"cred": {"totp": self.totp_code()}}]
        else:
            steps += [{"begin": "password"}]
        steps += [{"cred": {"password": password}}]
        for step in steps:
            r = http.request("POST", self.base + "/v1/auth", json={"step": step}, headers=headers)
            assert r.status_code == 200, (r.status_code, r.text)
            if "x-kanidm-auth-session-id" in r.headers:
                headers["x-kanidm-auth-session-id"] = r.headers["x-kanidm-auth-session-id"]
            body = r.json()
        return {"Authorization": "Bearer " + secret(body["state"]["success"])}

    def provision_kanidm(self):
        recovery = run(
            "docker",
            "exec",
            self.container,
            "kanidmd",
            "scripting",
            "recover-account",
            "idm_admin",
        )
        # Never print recovery output: it contains a new privileged password.
        obj = json.loads(recovery)
        password = secret(obj["output"])
        self.admin = self.kanidm_login("idm_admin", password)

        def api(method, path, data):
            return self.http.json(method, self.base + path, headers=self.admin, json=data)

        api("POST", "/v1/group", {"attrs": {"name": ["lake-readers"]}})
        api(
            "POST",
            "/v1/service_account",
            {
                "attrs": {
                    "name": ["machine"],
                    "displayname": ["Machine"],
                    "entry_managed_by": ["idm_admin"],
                }
            },
        )
        api("POST", "/v1/person", {"attrs": {"name": ["alice"], "displayname": ["Alice Test"]}})
        api("POST", "/v1/group/lake-readers/_attr/member", ["machine", "alice"])
        for name in ("lakekeeper", "wrong-audience"):
            api(
                "POST",
                "/v1/oauth2/_basic",
                {
                    "attrs": {
                        "name": [name],
                        "displayname": [name],
                        "oauth2_rs_origin_landing": [CALLBACK],
                        "oauth2_strict_redirect_uri": ["true"],
                    }
                },
            )
            api("POST", f"/v1/oauth2/{name}/_attr/oauth2_rs_origin", [CALLBACK])
            api("POST", f"/v1/oauth2/{name}/_scopemap/lake-readers", SCOPE.split())
        self.client_secret = secret(
            self.http.json(
                "GET", self.base + "/v1/oauth2/lakekeeper/_basic_secret", headers=self.admin
            )
        )
        self.service_token = secret(
            api(
                "POST",
                "/v1/service_account/machine/_api_token",
                {"label": "bakeoff", "expiry": None, "read_write": False, "compact": False},
            )
        )
        # Reset credential through the supported credential-update API, not DB edits.
        update = self.http.json(
            "GET", self.base + "/v1/person/alice/_credential/_update", headers=self.admin
        )
        session = update[0]
        secret(session["token"])
        api("POST", "/v1/credential/_update", [{"password": self.password}, session])
        state = api("POST", "/v1/credential/_update", ["totpgenerate", session])
        self.totp = state["mfaregstate"]["TotpCheck"]
        secret(json.dumps(self.totp["secret"]))
        secret(base64.b32encode(bytes(self.totp["secret"])).decode().rstrip("="))
        status = api(
            "POST", "/v1/credential/_update", [{"totpverify": [self.totp_code(), "CI"]}, session]
        )
        assert status["can_commit"], "Kanidm credential policy not satisfied"
        api("POST", "/v1/credential/_commit", session)

    def totp_code(self):
        counter = int(time.time()) // self.totp["step"]
        digest = hmac.new(
            bytes(self.totp["secret"]), counter.to_bytes(8, "big"), self.totp["algo"]
        ).digest()
        offset = digest[-1] & 15
        return (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF) % (
            10 ** self.totp["digits"]
        )

    def machine(self, client="lakekeeper"):
        return self.http.request(
            "POST",
            self.discovery["token_endpoint"],
            data={
                "grant_type": "client_credentials",
                "client_id": client,
                "client_secret": self.client_secret,
            },
        )

    def exchange(self, client="lakekeeper"):
        return self.http.json(
            "POST",
            self.discovery["token_endpoint"],
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": client,
                "subject_token": self.service_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "audience": client,
                "scope": SCOPE,
            },
        )

    def human(self):
        verifier, code_challenge = challenge()
        state, nonce = secret(), secret()
        params = {
            "client_id": "lakekeeper",
            "response_type": "code",
            "redirect_uri": CALLBACK,
            "scope": "openid profile" if self.name == "keycloak" else SCOPE,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        http = HTTPS(self.ca)
        if self.name == "kanidm":
            headers = self.kanidm_login("alice", self.password)
            r = http.request(
                "GET", self.base + "/oauth2/authorise?" + urlencode(params), headers=headers
            )
            assert r.status_code == 200, (r.status_code, r.text)
            body = r.json()
            if "ConsentRequested" in body:
                consent = secret(body["ConsentRequested"]["consent_token"])
                r = http.request(
                    "POST", self.base + "/oauth2/authorise/permit", json=consent, headers=headers
                )
                assert r.status_code in (200, 302), (r.status_code, r.text)
                location = r.headers.get("Location") or r.json()
            else:
                location = body["permitted"]["redirect_uri"]
        else:
            r = http.request(
                "GET", self.discovery["authorization_endpoint"] + "?" + urlencode(params)
            )
            assert r.status_code == 200, (r.status_code, r.text)
            if self.name == "keycloak":
                form = Form(r.text)
                assert form.action, "Missing Keycloak login form"
                r = http.request(
                    "POST",
                    urljoin(r.url, form.action),
                    data={**form.fields, "username": "alice", "password": self.password},
                )
                assert r.status_code == 302, (r.status_code, r.text)
            else:
                match = re.search(r'<template id="tpl_csrf_token">(.*?)</template>', r.text)
                assert match, "Missing Rauthy CSRF token"
                csrf = secret(match[1])
                headers = {"x-csrf-token": csrf, "Origin": self.base}
                pow_response = http.request("POST", self.base + "/auth/v1/pow", headers=headers)
                assert pow_response.status_code == 200, (
                    pow_response.status_code,
                    pow_response.text,
                )
                work = pow_response.text
                difficulty = int(work[2:4])
                assert 0 < difficulty <= 26, difficulty
                deadline = time.monotonic() + 60
                counter = 0
                while True:
                    solved = work + str(counter)
                    if (
                        int.from_bytes(hashlib.sha256(solved.encode()).digest(), "big")
                        >> (256 - difficulty)
                        == 0
                    ):
                        break
                    counter += 1
                    if counter % 10000 == 0:
                        assert time.monotonic() < deadline, "PoW timeout"
                r = http.request(
                    "POST",
                    self.discovery["authorization_endpoint"],
                    headers=headers,
                    json={
                        **{k: v for k, v in params.items() if k not in ("scope", "response_type")},
                        "scopes": SCOPE.split(),
                        "email": "alice@idp.test",
                        "password": self.password,
                        "pow": solved,
                    },
                )
                assert r.status_code == 202, (r.status_code, r.text)
            location = r.headers["Location"]
        assert location.startswith(CALLBACK + "?"), location
        values = parse_qs(urlsplit(location).query)
        assert values["state"] == [state], "State mismatch"
        code = secret(values["code"][0])
        token = self.http.json(
            "POST",
            self.discovery["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "client_id": "lakekeeper",
                "client_secret": self.client_secret,
                "redirect_uri": CALLBACK,
                "code": code,
                "code_verifier": verifier,
            },
        )
        for key in ("access_token", "id_token", "refresh_token"):
            if key in token:
                secret(token[key])
        assert decode(token["id_token"])[1]["nonce"] == nonce
        return token

    def rotate(self):
        if self.name == "keycloak":
            realm = self.http.json("GET", self.base + "/admin/realms/bakeoff", headers=self.admin)
            return self.http.json(
                "POST",
                self.base + "/admin/realms/bakeoff/components",
                statuses=(201,),
                headers=self.admin,
                json={
                    "name": "bakeoff-rotation",
                    "parentId": realm["id"],
                    "providerId": "rsa-generated",
                    "providerType": "org.keycloak.keys.KeyProvider",
                    "config": {
                        "priority": ["200"],
                        "algorithm": ["RS256"],
                        "keySize": ["2048"],
                        "active": ["true"],
                        "enabled": ["true"],
                    },
                },
            )
        if self.name == "rauthy":
            return self.http.json(
                "POST", self.base + "/auth/v1/oidc/rotate_jwk", headers=self.admin
            )
        return self.http.json(
            "POST",
            self.base + "/v1/oauth2/lakekeeper/_attr/key_action_rotate",
            headers=self.admin,
            json=["2020-01-01T00:00:00Z"],
        )
