"""Cross-service TLS checks for the running lakehouse. Any unexpected outcome fails.

- exposure: exact listener inventory of every network namespace, plaintext refused
  on every exposed listener, loopback backends unreachable from other containers,
  verified handshakes and mTLS-required checks on every SeaweedFS listener.
- key_isolation: exact read-only mounts; each service sees only its own key.
- negatives: real clients (runner libraries, Trino, Sail, Lakekeeper, SeaweedFS's
  own client) against a mutation relay presenting wrong-CA, wrong-hostname and
  expired leaves, with valid controls before and after every mutation.
- seaweed_canaries: exact-outcome canaries for a known SeaweedFS limitation,
  reported upstream (see seaweedfs-ubi PR #81). A changed outcome fails for review.
"""

import ipaddress
import json
import re
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

NETWORK = "lakehouse-integration_private"
HERE = Path(__file__).resolve().parent
HTTP_LISTENERS = (
    ("catalog", 8181),
    ("trino", 8443),
    ("s3", 8333),
    ("master", 9333),
    ("volume", 8080),
    ("filer", 8888),
)
GRPC_LISTENERS = (
    ("sail", 50051),
    ("master", 19333),
    ("volume", 18080),
    ("filer", 18888),
    ("s3", 18333),
)
SEAWEED_LISTENERS = {
    ("master", 9333): False,
    ("volume", 8080): False,
    ("filer", 8888): False,
    ("master", 19333): True,
    ("volume", 18080): True,
    ("filer", 18888): True,
    ("s3", 18333): True,
}
# A trusted role certificate that the listener's identity allowlist excludes
# (the pinned seaweedfs-ubi qualification's role swaps).
DISALLOWED_ROLE = {
    "master": "s3-client",
    "volume": "volume-client",
    "filer": "master-client",
    "s3": "master-client",
}
# Default/old plaintext and backend ports that must refuse peers.
CLOSED = (
    ("trino", 8080),
    ("catalog", 8182),
    ("catalog", 9000),
    ("sail", 50052),
    ("s3", 8181),
    ("s3", 9101),
    ("s3", 8334),
)
EXPECTED_LISTENERS = {
    "postgres": {("tcp", "any", 5432)},
    "master": {("tcp", "any", 9333), ("tcp", "any", 19333)},
    "volume": {("tcp", "any", 8080), ("tcp", "any", 18080)},
    "filer": {("tcp", "any", 8888), ("tcp", "any", 18888)},
    "s3": {("tcp", "any", 8333), ("tcp", "any", 18333)},
    "catalog": {("tcp", "loopback", 8182), ("tcp", "loopback", 9000), ("tcp", "any", 8181)},
    "trino": {("tcp", "any", 8443)},
    "sail": {("tcp", "loopback", 50052), ("tcp", "any", 50051)},
}
NGINX_400 = b"The plain HTTP request was sent to HTTPS port"
GO_400 = b"Client sent an HTTP request to an HTTPS server.\n"
# nginx's generic page for a cleartext HTTP/2 preface on a TLS port (server_tokens off).
NGINX_GENERIC_400 = (
    b"<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n"
    b"<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx</center>\r\n"
    b"</body>\r\n</html>\r\n"
)
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00\x00\x00\x04\x00\x00\x00\x00\x00"
CERT_ALERTS = {42, 43, 44, 45, 46, 48}  # bad/unsupported/revoked/expired/unknown cert, unknown CA


def inspect(name):
    return json.loads(subprocess.check_output(["docker", "inspect", name]))[0]


def leaves(h):
    return h.RUNTIME / "pki/leaves"


# --------------------------------------------------------------------------- exposure


def decode(hex_address):
    address, port = hex_address.split(":")
    raw = bytes.fromhex(address)
    if len(raw) == 4:
        ip = ipaddress.IPv4Address(raw[::-1])
    else:
        ip = ipaddress.IPv6Address(b"".join(raw[i : i + 4][::-1] for i in range(0, 16, 4)))
        ip = ip.ipv4_mapped or ip
    return ip, int(port, 16)


def scope(ip):
    if str(ip) == "127.0.0.11":
        return "docker-dns"  # Docker's embedded resolver inside every namespace.
    if ip.is_loopback:
        return "loopback"
    if ip.is_unspecified:
        return "any"
    return "address:" + str(ip)


def listeners(pid):
    found = set()
    raw = []
    for table, state in (("tcp", "0A"), ("tcp6", "0A"), ("udp", "07"), ("udp6", "07")):
        text = subprocess.check_output(
            ["sudo", "nsenter", f"--net=/proc/{pid}/ns/net", "cat", f"/proc/net/{table}"], text=True
        )
        for line in text.splitlines()[1:]:
            fields = line.split()
            if fields[3] != state:
                continue
            ip, port = decode(fields[1])
            raw.append(f"{table} {ip}:{port}")
            kind = scope(ip)
            if kind != "docker-dns":
                found.add((table.rstrip("6"), kind, port))
    return found, sorted(raw)


def plaintext(host, port, payload, timeout=5):
    """Send cleartext to a TLS listener; classify the reply without trusting it."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as connection:
            connection.sendall(payload)
            data = b""
            while len(data) < 8192:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                data += chunk
    except ConnectionResetError:
        return "reset", b""
    except TimeoutError:
        return "UNEXPECTED-timeout", b""
    except OSError as exc:
        return "UNEXPECTED-" + type(exc).__name__, b""
    return classify(data)


def classify(data):
    """Only a close, a TLS alert record or the exact protocol-error page pass."""
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n")[0]
    if data == b"":
        return "closed", data
    if data[:1] == b"\x15" and data[1:2] == b"\x03":
        return "tls-alert", data[:7]
    if status.startswith(b"HTTP/1.") and b" 400 " in status + b" ":
        if NGINX_400 in body or body in (GO_400, NGINX_GENERIC_400):
            return "protocol-error-400", status
    return "UNEXPECTED", data[:200]


def http_payload(host, port):
    return f"GET / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode()


def pg_plaintext():
    """A startup message without SSLRequest, and no password: must be refused."""
    body = b"user\x00lakekeeper\x00database\x00lakekeeper\x00\x00"
    message = struct.pack("!ii", 8 + len(body), 196608) + body
    with socket.create_connection(("postgres", 5432), timeout=5) as connection:
        connection.sendall(message)
        reply = connection.recv(4096)
    text = reply.decode(errors="replace")
    refused = reply[:1] == b"E" and "no pg_hba.conf entry" in text and "no encryption" in text
    return ("refused-before-authentication" if refused else "UNEXPECTED"), text[5:200]


def refused_from_container():
    """Connect attempts from a separate, hardened container on the private network."""
    script = (
        "import json,socket\n"
        f"targets={json.dumps(CLOSED)}\n"
        "out={}\n"
        "for host,port in targets:\n"
        "    try:\n"
        "        socket.create_connection((host,port),timeout=5).close(); out[f'{host}:{port}']='CONNECTED'\n"
        "    except ConnectionRefusedError: out[f'{host}:{port}']='refused'\n"
        "    except Exception as e: out[f'{host}:{port}']=type(e).__name__\n"
        "print(json.dumps(out))\n"
    )
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--network", NETWORK, "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--user", "10001:10001",
            "--entrypoint", "/usr/bin/python3.12", "localhost/sail-ubi:integration",
            "-I", "-B", "-c", script,
        ],
        capture_output=True, text=True, check=True, timeout=60,
    )  # fmt: skip
    return json.loads(result.stdout.strip().splitlines()[-1])


def client_context(h, cert=None, ca="ca"):
    context = ssl.create_default_context(cafile=leaves(h) / f"{ca}.crt")
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    if cert:
        context.load_cert_chain(leaves(h) / f"{cert}.crt", leaves(h) / f"{cert}.key")
    return context


def handshake(h, host, port, grpc, cert=None):
    """Verified handshake plus a first application exchange (TLS 1.3 client-cert
    verdicts arrive after the handshake). Returns evidence or raises."""
    context = client_context(h, cert)
    if grpc:
        context.set_alpn_protocols(["h2"])
    with socket.create_connection((host, port), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secure:
            peer = secure.getpeercert()
            evidence = {
                "version": secure.version(),
                "cipher": secure.cipher()[0],
                "alpn": secure.selected_alpn_protocol(),
                "san": [value for kind, value in peer.get("subjectAltName", ()) if kind == "DNS"],
                "not_after": peer["notAfter"],
            }
            secure.sendall(H2_PREFACE if grpc else http_payload(host, port))
            first = secure.recv(64)
            assert first, "Listener closed the verified connection without a response"
            evidence["response"] = "h2-frames" if grpc else first.split(b"\r\n")[0].decode()
    assert evidence["version"] in ("TLSv1.2", "TLSv1.3"), evidence
    assert evidence["san"] == [host], evidence
    return evidence


def mtls_refused(h, host, port, grpc, cert):
    try:
        handshake(h, host, port, grpc, cert)
    except ssl.SSLError as exc:
        message = str(exc)
        assert re.search(r"alert|certificate", message, re.I), message
        return message[:160]
    except (ConnectionResetError, BrokenPipeError) as exc:
        raise AssertionError(f"{host}:{port} {cert}: no TLS-specific refusal ({exc!r})") from exc
    raise AssertionError(f"{host}:{port} accepted client identity {cert!r}")


def exposure(h):
    h.hosts()
    report = {"listeners": {}, "plaintext": {}, "closed": {}, "tls": {}, "mtls": {}}
    owners = dict(EXPECTED_LISTENERS)
    for service, expected in owners.items():
        found, raw = listeners(inspect(h.cid(service))["State"]["Pid"])
        report["listeners"][service] = raw
        assert found == expected, (service, sorted(found), sorted(expected))
    for proxy, owner in h.PROXIES.items():
        assert inspect(h.cid(proxy))["HostConfig"]["NetworkMode"] == "container:" + h.cid(owner)
    for host, port in HTTP_LISTENERS:
        outcome, detail = plaintext(host, port, http_payload(host, port))
        report["plaintext"][f"{host}:{port}"] = [outcome, repr(detail)]
        assert not outcome.startswith("UNEXPECTED"), (host, port, outcome, detail)
    body = b"Action=AssumeRole&Version=2011-06-15"
    post = (
        b"POST / HTTP/1.1\r\nHost: s3:8333\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    outcome, detail = plaintext("s3", 8333, post)
    report["plaintext"]["s3:8333 root POST"] = [outcome, repr(detail)]
    assert not outcome.startswith("UNEXPECTED"), (outcome, detail)
    for host, port in GRPC_LISTENERS:
        outcome, detail = plaintext(host, port, H2_PREFACE)
        report["plaintext"][f"{host}:{port}"] = [outcome, repr(detail)]
        assert not outcome.startswith("UNEXPECTED"), (host, port, outcome, detail)
    outcome, detail = pg_plaintext()
    report["plaintext"]["postgres:5432"] = [outcome, detail]
    assert outcome == "refused-before-authentication", detail
    for host, port in CLOSED:
        try:
            socket.create_connection((host, port), timeout=5).close()
            outcome = "CONNECTED"
        except ConnectionRefusedError:
            outcome = "refused"
        except OSError as exc:
            outcome = type(exc).__name__
        report["closed"][f"runner->{host}:{port}"] = outcome
        assert outcome == "refused", (host, port, outcome)
    peer = refused_from_container()
    report["closed"]["container"] = peer
    assert peer == {f"{host}:{port}": "refused" for host, port in CLOSED}, peer
    for host, port in HTTP_LISTENERS + GRPC_LISTENERS:
        grpc = (host, port) in GRPC_LISTENERS
        cert = "probe-client" if (host, port) in SEAWEED_LISTENERS else None
        report["tls"][f"{host}:{port}"] = handshake(h, host, port, grpc, cert)
    for (host, port), grpc in SEAWEED_LISTENERS.items():
        cases = {
            "no-client-cert": None,
            "untrusted-client": "untrusted-client",
            "expired-client": "expired-client",
        }
        if grpc:
            cases["disallowed-role"] = DISALLOWED_ROLE[host]
        for case, cert in cases.items():
            handshake(h, host, port, grpc, "probe-client")  # valid control before
            report["mtls"][f"{host}:{port} {case}"] = mtls_refused(h, host, port, grpc, cert)
            handshake(h, host, port, grpc, "probe-client")  # valid control after
    return report


# ----------------------------------------------------------------------- key isolation


def key_isolation(h):
    runtime, sources = h.RUNTIME.resolve(), (h.ROOT / ".sources").resolve()
    tls = runtime / "tls"
    expected = {
        "postgres": {"/run/secrets": runtime / "postgres", "/run/tls": tls / "postgres"},
        "master": {"/etc/seaweedfs": tls / "master"},
        "volume": {"/etc/seaweedfs": tls / "volume"},
        "filer": {"/etc/seaweedfs": tls / "filer"},
        "s3": {"/run/secrets": runtime / "s3", "/etc/seaweedfs": tls / "s3"},
        "catalog": {"/run/tls": tls / "trust"},
        "catalog-proxy": {
            "/etc/nginx/profile/nginx.conf": sources
            / "nginx-ubi/examples/profiles/lakekeeper/nginx.conf",
            "/etc/nginx/tls": tls / "catalog-proxy",
        },
        "trino": {"/etc/trino": runtime / "trino", "/run/tls": tls / "trino"},
        "sail": {
            "/etc/sail/config.json": h.ROOT.resolve() / "integration/sail/config.json",
            "/run/tls": tls / "trust",
        },
        "sail-proxy": {
            "/etc/nginx/profile/nginx.conf": sources
            / "nginx-ubi/examples/profiles/sail/nginx.conf",
            "/etc/nginx/tls": tls / "sail-proxy",
        },
    }
    report = {}
    for service, mounts in expected.items():
        item = inspect(h.cid(service))
        binds = {m["Destination"]: m for m in item["Mounts"] if m["Type"] == "bind"}
        assert set(binds) == set(mounts), (service, sorted(binds))
        for destination, source in mounts.items():
            assert not binds[destination]["RW"], (service, destination)
            assert Path(binds[destination]["Source"]).resolve() == source, (service, destination)
        report[service] = sorted(mounts)
    # The proxy profiles are the pinned files, unmodified.
    status = subprocess.check_output(
        ["git", "-C", str(sources / "nginx-ubi"), "status", "--porcelain"], text=True
    )
    assert status == "", status
    # Public trust holds exactly one public certificate; keys are root:0 0440.
    listing = subprocess.check_output(["sudo", "ls", "-A", str(tls / "trust")], text=True).split()
    assert listing == ["ca.crt"], listing
    modes = subprocess.check_output(
        ["sudo", "find", str(tls), "-type", "f", "-name", "*.key", "-printf", "%u:%g %m %p\n"],
        text=True,
    ).splitlines()
    assert modes and all(line.startswith("root:root 440 ") for line in modes), modes
    pems = subprocess.check_output(
        ["sudo", "grep", "-rl", "PRIVATE KEY", str(tls)], text=True
    ).split()
    allowed = {"server.key", "server.pem", "grpc.key", "http.key", "client.key"}
    assert all(Path(path).name in allowed for path in pems), pems
    # The catalog application cannot read its proxy's key, nor S3 any other key.
    for service, path in (
        ("catalog", "/etc/nginx/tls/server.key"),
        ("s3", "/run/tls/server.key"),
        ("s3", "/etc/nginx/tls/server.key"),
        ("trino", "/etc/seaweedfs/client.key"),
    ):
        result = subprocess.run(h.DC + ["exec", "-T", service, "cat", path], capture_output=True)
        assert result.returncode != 0 and b"No such file" in result.stderr, (service, path)
    report["private_keys"] = len(modes)
    return report


# --------------------------------------------------------------------- one-off helpers

HARDENED = [
    "--read-only",
    "--cap-drop=ALL",
    "--security-opt=no-new-privileges:true",
    "--pids-limit=512",
]


def oneoff(h, name, image, user, mounts, args, add_hosts=None, env_file=None, env=None, detach=False,
           tmpfs=(), extra=(), input=None, timeout=180):  # fmt: skip
    command = ["docker", "run", "--name", name, "--network", NETWORK, "--user", user, *HARDENED]
    for source, destination in mounts:
        command += ["-v", f"{source}:{destination}:ro"]
    for host, address in (add_hosts or {}).items():
        command += ["--add-host", f"{host}:{address}"]
    for mount in tmpfs:
        command += ["--tmpfs", mount]
    if env_file:
        command += ["--env-file", str(env_file)]
    for key, value in (env or {}).items():
        command += ["-e", f"{key}={value}"]
    command += list(extra)
    command += ["-d"] if detach else ["-i"]
    command += [image, *args]
    result = subprocess.run(command, input=input, capture_output=True, text=True, timeout=timeout)
    h.check_container_config(inspect(name))
    return result


def remove(*names):
    for name in names:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


def address(name):
    return inspect(name)["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]


def logs(name, since):
    result = subprocess.run(
        ["docker", "logs", "--since", since, name], capture_output=True, text=True
    )
    return result.stdout + result.stderr


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


# ------------------------------------------------------------------- SeaweedFS canaries

STRICT_REJECTION = "AuthenticateServer: untrusted server identity [master master]"


def seaweed_canaries(h):
    """Exact-outcome canaries for a known SeaweedFS limitation, reported upstream.

    Both must reproduce exactly; a changed outcome fails so the interim trust
    setting (tls_setup.S3_OUTBOUND) is reviewed rather than silently kept.
    """
    report = {}
    name = "lakehouse-integration-s3-strict-canary"
    remove(name)
    tls = h.RUNTIME / "tls"
    try:
        oneoff(
            h, name, "localhost/seaweedfs-ubi:integration", "1000:0",
            [(h.RUNTIME / "s3", "/run/secrets"), (tls / "s3-strict-canary", "/etc/seaweedfs")],
            ["s3", "-ip.bind=0.0.0.0", "-filer=filer:8888", "-config=/run/secrets/s3.json",
             "-cert.file=/etc/seaweedfs/http.crt", "-key.file=/etc/seaweedfs/http.key",
             "-port.iceberg=0", "-port.lance=0"],
            detach=True,
        )  # fmt: skip
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline and STRICT_REJECTION not in logs(name, "0"):
            time.sleep(2)
        strict = STRICT_REJECTION in logs(name, "0")
    finally:
        remove(name)
    if not strict:
        raise AssertionError(
            "Outcome changed: the strict single-target S3 gRPC policy no longer reproduces the "
            "known SeaweedFS limitation. Review and narrow the interim S3 trust setting."
        )
    report["strict_policy"] = "reproduced exactly: " + STRICT_REJECTION
    production = logs(h.cid("s3"), "0")
    assert "untrusted server identity" not in production, "Integration S3 rejected a peer"
    report["interim_policy"] = "integration S3 outbound trust 'filer,master' admits both peers"
    return report


# ------------------------------------------------------------ certificate negatives

RELAY = "lakehouse-integration-tls-relay"
RELAY_PORTS = {
    "catalog": 8181,
    "s3": 8333,
    "trino": 8443,
    "sail": 50051,
    "master": 19333,
    "filer": 18888,
}
RELAY_CONF = """worker_processes 1;
pid /tmp/nginx.pid;
error_log /dev/stderr info;
events { worker_connections 256; }
http {
    log_format probe '$server_port $remote_addr "$request" $status';
    access_log /dev/stdout probe;
    client_body_temp_path /tmp/body;
    proxy_temp_path /tmp/proxy;
    fastcgi_temp_path /tmp/fastcgi;
    uwsgi_temp_path /tmp/uwsgi;
    scgi_temp_path /tmp/scgi;
    client_max_body_size 64m;
    ssl_protocols TLSv1.2 TLSv1.3;
    # No resumption: every connection must present (and verify) the current leaf.
    ssl_session_cache off;
    ssl_session_tickets off;
    proxy_http_version 1.1;
    proxy_next_upstream off;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_read_timeout 120s;
    proxy_ssl_verify on;
    proxy_ssl_verify_depth 2;
    proxy_ssl_server_name on;
    proxy_ssl_trusted_certificate /etc/nginx/relay/ca.crt;
    grpc_ssl_verify on;
    grpc_ssl_verify_depth 2;
    grpc_ssl_server_name on;
    grpc_ssl_trusted_certificate /etc/nginx/relay/ca.crt;
    grpc_read_timeout 300s;
%SERVERS%
}
"""


def relay_conf():
    servers = []
    for name, port in RELAY_PORTS.items():
        h2 = "        http2 on;\n" if port in (50051, 19333, 18888) else ""
        tls = f"        ssl_certificate /etc/nginx/relay/{name}.crt;\n        ssl_certificate_key /etc/nginx/relay/{name}.key;\n"
        if name == "sail":
            location = "grpc_pass grpcs://sail:50051; grpc_ssl_name sail;"
        elif name in ("master", "filer"):
            location = "return 403;"  # Terminating impostor: only the handshake matters.
        else:
            location = f"proxy_pass https://{name}:{port}; proxy_ssl_name {name}; proxy_set_header Host $http_host;"
        servers.append(
            f"    server {{\n        listen {port} ssl;\n{h2}{tls}        location / {{ {location} }}\n    }}"
        )
    return RELAY_CONF.replace("%SERVERS%", "\n".join(servers))


class Relay:
    """A verified TLS-to-TLS mutation relay on the private network (nginx-ubi)."""

    def __init__(self, h):
        self.h = h
        self.directory = h.RUNTIME / "relay"
        self.state = {}

    def install(self, name, variant):
        from tls_setup import install

        for ext in ("crt", "key"):
            install(leaves(self.h) / f"{name}-{variant}.{ext}", self.directory / f"{name}.{ext}")
        self.state[name] = variant

    def start(self):
        work = self.h.RUNTIME / "relay-work"
        work.mkdir()
        (work / "nginx.conf").write_text(relay_conf())
        subprocess.run(["sudo", "mkdir", "-m", "0750", str(self.directory)], check=True)
        from tls_setup import install

        install(work / "nginx.conf", self.directory / "nginx.conf", "0444")
        install(leaves(self.h) / "ca.crt", self.directory / "ca.crt", "0444")
        (work / "nginx.conf").unlink()
        work.rmdir()
        for name in RELAY_PORTS:
            self.install(name, "valid")
        remove(RELAY)
        oneoff(
            self.h, RELAY, "localhost/nginx-ubi:integration", "10001:0",
            [(self.directory, "/etc/nginx/relay")],
            ["-c", "/etc/nginx/relay/nginx.conf", "-g", "daemon off;"],
            tmpfs=["/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"], detach=True,
        )  # fmt: skip
        self.address = address(RELAY)
        self.wait()

    def fingerprint(self, name):
        text = subprocess.run(
            ["openssl", "x509", "-in", str(leaves(self.h) / f"{name}-{self.state[name]}.crt"),
             "-noout", "-fingerprint", "-sha256"],
            capture_output=True, text=True, check=True,
        ).stdout  # fmt: skip
        return text.strip().split("=", 1)[1]

    def served(self, name):
        """Inspect (not trust) the leaf the relay currently serves on a port."""
        hello = subprocess.run(
            ["openssl", "s_client", "-connect", f"{self.address}:{RELAY_PORTS[name]}",
             "-servername", name],
            input="", capture_output=True, text=True, timeout=15,
        )  # fmt: skip
        parsed = subprocess.run(
            ["openssl", "x509", "-noout", "-fingerprint", "-sha256"],
            input=hello.stdout, capture_output=True, text=True,
        )  # fmt: skip
        return parsed.stdout.strip().split("=", 1)[-1]

    def wait(self):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if all(self.served(name) == self.fingerprint(name) for name in RELAY_PORTS):
                return
            time.sleep(0.5)
        raise AssertionError("Relay did not serve the requested leaves: " + json.dumps(self.state))

    def set(self, name, variant):
        if self.state.get(name) == variant:
            return
        self.install(name, variant)
        subprocess.run(["docker", "kill", "--signal=HUP", RELAY], check=True, capture_output=True)
        self.wait()
        time.sleep(1)  # Let old workers finish closing their idle connections.

    def evidence(self, since, port, client):
        text = logs(RELAY, since)
        # The client hung up without an alert, before sending any request.
        closed = re.search(
            r"(?:peer closed connection in SSL handshake[^\n]*while SSL handshaking"
            r"|client closed connection while (?:waiting for request|processing HTTP/2 connection))"
            rf", client: {re.escape(client)}, server: [^,]*:{port}\b",
            text,
        )
        requests = [
            line for line in text.splitlines() if re.match(rf"^{port} {re.escape(client)} ", line)
        ]
        alerts = [
            int(match.group(1))
            for match in re.finditer(
                rf"SSL alert number (\d+)\) while SSL handshaking, client: {re.escape(client)}, server: [^,]*:{port}\b",
                text,
            )
        ]
        return requests, alerts, bool(closed)


def runner_client(
    h, mode, argument="", hosts=None, python=None, query=None, payload=None, netns_pid=None
):
    """A fresh client process. hosts: names to resolve to given addresses."""
    import os

    env = dict(
        os.environ,
        PROBE_ACCESS=h.CREDS["access"],
        PROBE_SECRET=h.CREDS["secret"],
        PROBE_QUERY=query or "",
        PROBE_PAYLOAD=json.dumps(payload or {}),
    )
    command = [python or sys.executable, str(HERE / "tls_clients.py"), mode, argument]
    if netns_pid:
        # Enter only the probe's network namespace, as the unprivileged runner user.
        keep = ["SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "AWS_CA_BUNDLE",
                "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", "PROBE_ACCESS", "PROBE_SECRET",
                "PROBE_QUERY", "PROBE_PAYLOAD", "HOME", "PATH"]  # fmt: skip
        command = [
            "sudo", "nsenter", f"--net=/proc/{netns_pid}/ns/net",
            f"--setuid={os.getuid()}", f"--setgid={os.getgid()}",
            "env", *[f"{key}={env[key]}" for key in keep if key in env], *command,
        ]  # fmt: skip
    if hosts:
        h.hosts(hosts)
    try:
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=300)
    finally:
        if hosts:
            h.hosts()
    line = next((x for x in result.stdout.splitlines() if x.startswith("CLIENT_RESULT=")), None)
    assert line, ("Client produced no result", mode, result.returncode, result.stderr[-3000:])
    return json.loads(line.removeprefix("CLIENT_RESULT="))


CLIENT_PATTERNS = {
    "wrong-ca": r"(?i)unknown.?(ca|issuer)|unable to get local issuer|self.signed|PKIX|certification path|certificate verify failed|CERTIFICATE_VERIFY_FAILED|curlCode: 60|UnknownIssuer|unknown authority",
    "wrong-san": r"(?i)Peer name \S+ is not in peer certificate|hostname mismatch|doesn't match|not valid for|Hostname Verification Check failed\.|No subject alternative|NotValidForName|certificate verify failed|CERTIFICATE_VERIFY_FAILED|curlCode: 60|bad certificate",
    "expired": r"(?i)expired|NotAfter|validity check failed|certificate verify failed|CERTIFICATE_VERIFY_FAILED|curlCode: 60|Expired",
}


# Exact verifier diagnoses (Python ssl, curl/OpenSSL in the AWS C++ SDK, gRPC core).
EXACT_VERIFY_FAILURE = {
    "wrong-ca": (
        r"certificate verify failed: unable to get local issuer"
        r"|verify result: unable to get local issuer certificate \(20\)"
        r"|CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate: OK"
    ),
    "wrong-san": (
        r"certificate verify failed: Hostname mismatch"
        r"|no alternative certificate subject name matches target host ?name"
        r"|hostname '\S+' doesn't match 'wrong\.invalid'"
        r"|Certificate for <\S+> doesn't match any of the subject alternative names: \[wrong\.invalid\]"
        r"|Peer name \S+ is not in peer certificate"
        r"|Custom verification check failed with error: UNAUTHENTICATED: Hostname Verification Check failed\."
    ),
    "expired": (
        r"certificate verify failed: certificate has expired"
        r"|verify result: certificate has expired \(10\)"
        r"|CERTIFICATE_VERIFY_FAILED: certificate has expired: OK"
    ),
}


class Matrix:
    def __init__(self, h, relay):
        self.h, self.relay, self.rows = h, relay, []
        gateway = json.loads(subprocess.check_output(["docker", "network", "inspect", NETWORK]))[0]
        self.runner = gateway["IPAM"]["Config"][0]["Gateway"]

    def row(self, edge, variant, outcome, detail):
        self.rows.append({"edge": edge, "variant": variant, "outcome": outcome, "detail": detail})
        print(f"TLS {edge} {variant}: {outcome} {detail}"[:600], flush=True)

    def case(self, edge, target, variant, call, client_ip, pattern=True):
        """call() -> (ok, error_text). Mutations must fail with TLS evidence."""
        self.relay.set(target, variant)
        since = now()
        ok, text = call()
        time.sleep(0.5)
        port = RELAY_PORTS[target]
        requests, alerts, closed = self.relay.evidence(since, port, client_ip)
        if variant == "valid":
            assert ok, (edge, "valid control failed", text[-2000:])
            self.row(edge, variant, "accepted", f"{len(requests)} relayed requests")
            return
        assert not ok, (edge, variant, "MUTATED CERTIFICATE ACCEPTED", text[-500:])
        assert not requests, (
            edge,
            variant,
            "application request after mutated handshake",
            requests,
        )
        # Some clients verify after the handshake (curl in the AWS C++ SDK, gRPC's
        # peer-name check) or abort without flushing an alert (asyncio). Then the
        # relay must record that client hanging up and the client the exact reason.
        diagnosis = re.search(EXACT_VERIFY_FAILURE[variant], text)
        silent = closed and diagnosis
        if not silent:
            assert alerts and set(alerts) <= CERT_ALERTS, (
                edge,
                variant,
                "no certificate alert",
                alerts,
                text[-1500:],
            )
        matched = re.search(CLIENT_PATTERNS[variant], text) if pattern else None
        assert matched or not pattern, (
            edge,
            variant,
            "client error is not TLS-specific",
            text[-1500:],
        )
        self.row(
            edge,
            variant,
            "refused",
            {
                "alerts": sorted(set(alerts)),
                "client": matched.group(0) if matched else "relay alert only",
                "requests": len(requests),
                "client_hangup": closed,
                "exact_diagnosis": diagnosis.group(0) if diagnosis else None,
            },
        )

    def edge(self, edge, target, call, client_ip, pattern=True):
        self.case(edge, target, "valid", call, client_ip, pattern)
        for variant in ("wrong-ca", "wrong-san", "expired"):
            self.case(edge, target, variant, call, client_ip, pattern)
            self.case(edge, target, "valid", call, client_ip, pattern)
        self.relay.set(target, "valid")


def result_call(result_fn):
    def call():
        result = result_fn()
        return result["ok"], json.dumps(result)

    return call


def failure_chain(error):
    """Trino's error as its cause chain ("type: message"), without stack frames."""
    lines = [f"{error.get('errorName')}: {error.get('message')}"]
    info = error.get("failureInfo")
    while info:
        lines.append(f"{info.get('type')}: {info.get('message')}")
        lines += [
            f"suppressed {item.get('type')}: {item.get('message')}"
            for item in info.get("suppressed", [])
        ]
        info = info.get("cause")
    return "\n".join(lines)


class TrinoProbe:
    """A second, real Trino (same image/config/trust) whose catalog and S3 names
    resolve to the relay. Queried over verified HTTPS at its own address."""

    name = "lakehouse-integration-trino-probe"

    def __init__(self, h, relay_ip):
        self.h = h
        remove(self.name)
        oneoff(
            h, self.name, "localhost/trino-ubi:integration", "10001:0",
            [(h.RUNTIME / "trino", "/etc/trino"), (h.RUNTIME / "tls/trino", "/run/tls")],
            [], add_hosts={"catalog": relay_ip, "s3": relay_ip, "trino": "127.0.0.1"},
            env_file=h.RUNTIME / "trino.env", env={"TRINO_UBI_ALLOW_INSECURE": "true"},
            tmpfs=["/var/lib/trino:rw,noexec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=512m",
                   "/tmp/trino:rw,exec,nosuid,nodev,uid=10001,gid=0,mode=0750,size=256m"],
            extra=["--memory=2g"], detach=True,
        )  # fmt: skip
        self.ip = address(self.name)
        h.wait("Trino probe", lambda: self.request("GET", "/v1/info").get("starting") is False, 240)

    def request(self, method, path, body=None):
        import http.client

        connection = http.client.HTTPSConnection(
            "trino", 8443, context=self.h.tls_context(), timeout=60
        )
        raw = socket.create_connection((self.ip, 8443), timeout=60)
        connection.sock = self.h.tls_context().wrap_socket(raw, server_hostname="trino")
        headers = {"X-Trino-User": "integration"}
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = json.loads(response.read() or b"{}")
        connection.close()
        return data

    def sql(self, query):
        page = self.request("POST", "/v1/statement", query.encode())
        rows, deadline = [], time.monotonic() + 240
        while True:
            if "error" in page:
                return False, failure_chain(page["error"])
            rows.extend(page.get("data", []))
            if "nextUri" not in page:
                return True, json.dumps(rows)
            assert page["nextUri"].startswith("https://trino:8443/") and time.monotonic() < deadline
            time.sleep(0.2)
            page = self.request("GET", page["nextUri"].removeprefix("https://trino:8443"))


class SailProbe:
    """A second, real Sail engine whose catalog and S3 names resolve to the relay.
    Its Spark Connect listener is loopback-only; the runner's client enters only
    this probe's network namespace (no plaintext crosses a network)."""

    name = "lakehouse-integration-sail-probe"

    def __init__(self, h, relay_ip):
        self.h = h
        remove(self.name)
        compose = __import__("yaml").safe_load(
            (h.ROOT / "integration/compose.sail.yaml").read_text()
        )
        environment = compose["services"]["sail"]["environment"]
        oneoff(
            h, self.name, "localhost/sail-ubi:integration", "10001:10001",
            [(h.ROOT / "integration/sail/config.json", "/etc/sail/config.json"),
             (h.RUNTIME / "tls/trust", "/run/tls")],
            [], add_hosts={"catalog": relay_ip, "s3": relay_ip},
            env_file=h.RUNTIME / "sail.env", env=environment,
            tmpfs=["/tmp:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=10001,gid=10001",
                   "/var/lib/sail:rw,noexec,nosuid,nodev,size=256m,mode=0700,uid=10001,gid=10001"],
            extra=["--memory=2g"], detach=True,
        )  # fmt: skip
        self.pid = inspect(self.name)["State"]["Pid"]
        self.ip = address(self.name)
        h.wait(
            "Sail probe",
            lambda: subprocess.run(
                ["docker", "exec", self.name, "/usr/bin/python3.12", "-I", "-B", "/opt/sail/healthcheck.py"],
                capture_output=True,
            ).returncode == 0,
        )  # fmt: skip

    def query(self):
        return runner_client(
            self.h, "spark", "sc://127.0.0.1:50052",
            python=str(self.h.ROOT / ".sources/sail-venv/bin/python"),
            query="SELECT id FROM qualification.integration.from_trino ORDER BY id",
            netns_pid=self.pid,
        )  # fmt: skip


class CatalogProbe:
    """A second Lakekeeper server (same image, env and trust) whose S3 name resolves
    to the relay; exercises its S3 client by validating a new warehouse."""

    name = "lakehouse-integration-catalog-probe"

    def __init__(self, h, relay_ip):
        self.h, self.count = h, 0
        remove(self.name)
        # A separate disposable catalog avoids overlapping the main warehouse's
        # bucket-wide profile. Keep the same S3 credentials and verify-full URL.
        subprocess.run(
            h.DC + ["exec", "-T", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1",
                    "-h", "/tmp", "-U", "postgres", "-d", "lakekeeper", "-c",
                    "CREATE DATABASE tls_probe OWNER lakekeeper"],
            check=True, capture_output=True,
        )  # fmt: skip
        subprocess.run(
            h.DC + ["exec", "-T", "postgres", "psql", "-X", "-v", "ON_ERROR_STOP=1",
                    "-h", "/tmp", "-U", "postgres", "-d", "tls_probe", "-f",
                    "/usr/share/lakekeeper/init.sql"],
            check=True, capture_output=True,
        )  # fmt: skip
        database = {
            "LAKEKEEPER__PG_DATABASE_URL_WRITE": h.LAKEKEEPER_PG.format(
                h.CREDS["postgres"]
            ).replace("/lakekeeper?", "/tls_probe?")
        }
        migration = "lakehouse-integration-migrate-probe"
        try:
            result = oneoff(
                h, migration, "localhost/lakekeeper-ubi:integration", "999:0",
                [(h.RUNTIME / "tls/trust", "/run/tls")], ["migrate"],
                env_file=h.RUNTIME / "lakekeeper.env", env=database,
            )  # fmt: skip
            assert result.returncode == 0, result.stderr[-2000:]
        finally:
            remove(migration)
        oneoff(
            h, self.name, "localhost/lakekeeper-ubi:integration", "999:0",
            [(h.RUNTIME / "tls/trust", "/run/tls")], ["serve"],
            add_hosts={"s3": relay_ip}, env_file=h.RUNTIME / "lakekeeper.env",
            env=database, detach=True,
        )  # fmt: skip
        self.pid = inspect(self.name)["State"]["Pid"]
        self.ip = address(self.name)
        h.wait(
            "Lakekeeper probe",
            lambda: subprocess.run(
                ["docker", "exec", self.name, "lakekeeper", "healthcheck", "-s"], capture_output=True
            ).returncode == 0,
        )  # fmt: skip

    def warehouse(self):
        if self.count == 0:
            result = runner_client(self.h, "lakekeeper-bootstrap", netns_pid=self.pid)
            assert result["ok"], result
        self.count += 1
        payload = {
            "warehouse-name": f"tls-probe-{self.count}-{secrets.token_hex(3)}",
            "storage-profile": {
                "type": "s3", "bucket": "warehouse", "region": "local", "sts-enabled": False,
                "flavor": "s3-compat", "endpoint": "https://s3:8333", "path-style-access": True,
                "key-prefix": "tls-probe",
            },
            "storage-credential": {
                "type": "s3", "credential-type": "access-key",
                "access-key-id": self.h.CREDS["access"], "secret-access-key": self.h.CREDS["secret"],
            },
        }  # fmt: skip
        return runner_client(self.h, "lakekeeper-loopback", payload=payload, netns_pid=self.pid)


def weed_shell(h, name, master_host):
    """SeaweedFS's own Go gRPC client (provisioner identity) dialing master."""
    remove(name)
    hosts = {"master": master_host} if master_host else None
    try:
        result = oneoff(
            h, name, "localhost/seaweedfs-ubi:integration", "1000:0",
            [(h.RUNTIME / "tls/provisioner", "/etc/seaweedfs")],
            ["shell", "-master=master:9333", "-filer=filer:8888"], add_hosts=hosts,
            input="s3.bucket.list\n", timeout=25, extra=["--stop-timeout=1"],
        )  # fmt: skip
        return result.returncode == 0 and "warehouse" in result.stdout, result.stdout[
            -1500:
        ] + result.stderr[-1500:]
    except subprocess.TimeoutExpired as exc:
        return False, "shell timed out: " + str(exc.stdout)[-500:]
    finally:
        remove(name)


def seaweed_client_edges(h, matrix, relay):
    """Go gRPC client vs impostor master: wrong CA and expiry refused; the known
    limitation (no DNS-SAN binding) reproduces exactly for correct-CN/wrong-SAN."""
    name = "lakehouse-integration-weed-client"
    rows = {}
    ok, text = weed_shell(h, name, None)
    assert ok, ("real cluster control failed", text)
    for variant in ("valid", "wrong-ca", "wrong-san", "expired"):
        relay.set("master", variant)
        since = now()
        _, text = weed_shell(h, name, relay.address)
        requests = [line for line in logs(RELAY, since).splitlines() if line.startswith("19333 ")]
        alerts = [
            int(x)
            for x in re.findall(
                r"SSL alert number (\d+)\) while SSL handshaking, client: [^,]+, server: [^,]*:19333",
                logs(RELAY, since),
            )
        ]
        if variant in ("valid", "wrong-san"):
            # Handshake completed and the impostor received a gRPC request.
            assert requests and not alerts, (variant, requests, alerts, text)
            outcome = (
                "accepted"
                if variant == "valid"
                else "ACCEPTED (known SeaweedFS limitation, exact outcome)"
            )
        else:
            assert alerts and set(alerts) <= CERT_ALERTS and not requests, (
                variant,
                alerts,
                requests,
                text,
            )
            outcome = "refused"
        matrix.row(
            "seaweedfs-go-grpc->master",
            variant,
            outcome,
            {"alerts": sorted(set(alerts)), "requests": len(requests)},
        )
        rows[variant] = outcome
        ok, text = weed_shell(h, name, None)
        assert ok, ("real cluster control after mutation failed", variant, text)
    relay.set("master", "valid")
    return rows


def postgres_edges(h, matrix):
    """Lakekeeper's SQLx client (migrate) against a PostgreSQL impostor (real image)."""
    impostor = "lakehouse-integration-postgres-impostor"
    client = "lakehouse-integration-migrate-probe"
    work = h.RUNTIME / "pg-impostor"
    password = h.RUNTIME / "pg-impostor-password"
    subprocess.run(["sudo", "rm", "-rf", str(work)], check=True)
    password.write_text(secrets.token_hex(24))  # Impostor-only; never a real secret.
    password.chmod(0o600)
    for directory in (work, work / "secrets", work / "tls"):
        subprocess.run(["sudo", "mkdir", "-m", "0750", str(directory)], check=True)
    from tls_setup import install

    install(password, work / "secrets/postgres-password", "0440")
    password.unlink()

    def accepting():
        with socket.create_connection((address(impostor), 5432), timeout=3) as raw:
            raw.sendall(struct.pack("!ii", 8, 80877103))
            return raw.recv(1) == b"S"

    try:
        for variant in ("valid", "wrong-ca", "valid", "wrong-san", "valid", "expired", "valid"):
            remove(impostor, client)
            install(leaves(h) / f"postgres-{variant}.crt", work / "tls/server.crt", "0444")
            install(leaves(h) / f"postgres-{variant}.key", work / "tls/server.key", "0440")
            oneoff(
                h, impostor, "localhost/postgresql-lakekeeper-ubi:integration", "26:0",
                [(work / "secrets", "/run/secrets"), (work / "tls", "/run/tls")], [],
                env={"POSTGRES_USER": "postgres", "POSTGRES_DB": "lakekeeper",
                     "POSTGRES_PASSWORD_FILE": "/run/secrets/postgres-password",
                     "POSTGRESQL_TLS_CERT_FILE": "/run/tls/server.crt",
                     "POSTGRESQL_TLS_KEY_FILE": "/run/tls/server.key"},
                tmpfs=["/var/lib/pgsql:rw,nosuid,nodev,uid=26,gid=0,mode=0700,size=256m",
                       "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"], detach=True,
            )  # fmt: skip
            h.wait("PostgreSQL impostor", accepting, 90)
            since = now()
            result = oneoff(
                h, client, "localhost/lakekeeper-ubi:integration", "999:0",
                [(h.RUNTIME / "tls/trust", "/run/tls")], ["migrate"],
                add_hosts={"postgres": address(impostor)}, env_file=h.RUNTIME / "lakekeeper.env",
                timeout=120,
            )  # fmt: skip
            text = result.stdout + result.stderr
            server = logs(impostor, since)
            remove(client)
            if variant == "valid":
                # TLS verified; the impostor has no lakekeeper role, so SCRAM then fails.
                assert result.returncode != 0 and re.search(
                    r"password authentication failed|role \"lakekeeper\" does not exist",
                    text + server,
                ), text[-1500:]
                matrix.row(
                    "lakekeeper-sqlx->postgres",
                    variant,
                    "accepted (TLS), then authentication refused",
                    "",
                )
                continue
            assert result.returncode != 0, (variant, "migration succeeded against mutated server")
            assert re.search(
                r"could not accept SSL connection.*(alert|certificate)", server, re.I | re.S
            ), (variant, server[-1500:])
            assert "password authentication failed" not in server + text, (
                variant,
                "reached authentication",
            )
            matched = re.search(CLIENT_PATTERNS[variant] + r"|invalid peer certificate", text)
            assert matched, (variant, text[-1500:])
            matrix.row("lakekeeper-sqlx->postgres", variant, "refused", matched.group(0))
    finally:
        remove(impostor, client)
        subprocess.run(["sudo", "rm", "-rf", str(work)], check=True)


def negatives(h):
    relay = Relay(h)
    probes = []
    try:
        relay.start()
        matrix = Matrix(h, relay)
        ip = relay.address
        trino = TrinoProbe(h, ip)
        probes.append(trino.name)
        sail = SailProbe(h, ip)
        probes.append(sail.name)
        catalog = CatalogProbe(h, ip)
        probes.append(catalog.name)

        def runner(mode, argument, names):
            return result_call(
                lambda: runner_client(h, mode, argument, hosts={n: ip for n in names})
            )

        # Edge: clients of the catalog proxy (REST).
        url = "https://catalog:8181/catalog/v1/config?warehouse=qualification"
        matrix.edge(
            "python-ssl->catalog", "catalog", runner("urllib", url, ["catalog"]), matrix.runner
        )
        matrix.edge(
            "pyiceberg-rest->catalog",
            "catalog",
            runner("pyiceberg", "", ["catalog"]),
            matrix.runner,
        )
        matrix.edge(
            "trino-iceberg-rest->catalog",
            "catalog",
            lambda: trino.sql("SHOW TABLES FROM iceberg.integration"),
            trino.ip,
        )
        matrix.edge(
            "sail-rest->catalog", "catalog", result_call(sail.query), sail.ip, pattern=False
        )
        # Edge: clients of S3 (catalog stays valid).
        matrix.edge("pyarrow->s3", "s3", runner("pyarrow", "", ["s3"]), matrix.runner)
        matrix.edge("botocore->s3", "s3", runner("botocore", "", ["s3"]), matrix.runner)
        matrix.edge(
            "trino-s3->s3",
            "s3",
            lambda: trino.sql("SELECT * FROM iceberg.integration.from_trino ORDER BY id"),
            trino.ip,
        )
        matrix.edge("sail-object-store->s3", "s3", result_call(sail.query), sail.ip, pattern=False)
        matrix.edge(
            "lakekeeper-s3->s3", "s3", result_call(catalog.warehouse), catalog.ip, pattern=False
        )
        # Edges: Trino HTTPS and Sail Spark Connect clients.
        matrix.edge(
            "python-ssl->trino",
            "trino",
            runner("urllib", "https://trino:8443/v1/info", ["trino"]),
            matrix.runner,
        )
        spark = result_call(
            lambda: runner_client(
                h, "spark", "sc://sail:50051/;use_ssl=true", hosts={"sail": ip},
                python=str(h.ROOT / ".sources/sail-venv/bin/python"), query="SELECT 40 + 2",
            )
        )  # fmt: skip
        matrix.edge("pyspark-grpc->sail", "sail", spark, matrix.runner)
        seaweed = seaweed_client_edges(h, matrix, relay)
        postgres_edges(h, matrix)
    finally:
        # Sanitized at cleanup; the relay never logs headers or bodies.
        (h.REPORTS / "tls-relay.log").write_text(logs(RELAY, "0"))
        remove(*probes, RELAY)
        subprocess.run(["sudo", "rm", "-rf", str(h.RUNTIME / "relay")], check=True)
        h.hosts()
    refused = [row for row in matrix.rows if row["outcome"] == "refused"]
    return {"rows": matrix.rows, "refused": len(refused), "seaweedfs_go_client": seaweed}
