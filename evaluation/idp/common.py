"""Disposable IdP evaluation helpers. No production or main-fixture configuration."""

import base64
import hashlib
import json
import re
import secrets
import subprocess
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests

ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".runtime/idp"
OUT = ROOT / "reports/idp"
NETWORK = "idp-bakeoff"
SECRETS = []


def run(*args, **kwargs):
    result = subprocess.run(list(map(str, args)), capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"{args[0]} exited {result.returncode}: {result.stdout}{result.stderr}")
    return result.stdout.strip()


def secret(value=None):
    value = value or secrets.token_hex(32)
    SECRETS.append(value)
    # Persist BEFORE any operation that could fail, for always() cleanup.
    WORK.mkdir(parents=True, exist_ok=True)
    inventory = WORK / "secrets.json"
    inventory.write_text(json.dumps(SECRETS))
    inventory.chmod(0o600)
    print("::add-mask::" + value, flush=True)
    return value


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n" if not isinstance(data, str) else data)
    path.chmod(0o600)


def clean(text):
    for value in sorted(SECRETS, key=len, reverse=True):
        text = text.replace(value, "[REDACTED]")
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", "[JWT]", text)
    assert "PRIVATE KEY-----" not in text, "Private key in evidence"
    return text


def save(name, data):
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / name).write_text(clean(json.dumps(data, indent=2, default=str)) + "\n")


def wait(fn, seconds=120):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except Exception as exc:
            last = str(exc)
        time.sleep(1)
    raise RuntimeError(f"Readiness timeout ({seconds}s): {last}")


def pki():
    WORK.mkdir(parents=True, exist_ok=True)
    ca = WORK / "ca"
    ca.mkdir()
    run(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:3072",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=Disposable bakeoff CA",
        "-keyout",
        ca / "key.pem",
        "-out",
        ca / "ca.pem",
    )
    (ca / "key.pem").chmod(0o600)
    for name in (
        "kanidm",
        "rauthy",
        "keycloak",
        "catalog-kanidm",
        "catalog-rauthy",
        "catalog-keycloak",
    ):
        dest = WORK / name / "tls"
        dest.mkdir(parents=True)
        run(
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={name}.idp.test",
            "-keyout",
            dest / "key.pem",
            "-out",
            dest / "request.pem",
        )
        ext = dest / "extensions"
        ext.write_text(f"subjectAltName=DNS:{name}.idp.test\nextendedKeyUsage=serverAuth\n")
        run(
            "openssl",
            "x509",
            "-req",
            "-in",
            dest / "request.pem",
            "-CA",
            ca / "ca.pem",
            "-CAkey",
            ca / "key.pem",
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            ext,
            "-out",
            dest / "cert.pem",
        )
        (dest / "key.pem").chmod(0o600)
    return ca / "ca.pem"


class HTTPS:
    """Refuse plaintext and automatic redirects BEFORE transmitting credentials."""

    def __init__(self, ca):
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.verify = str(ca)

    def request(self, method, url, **kwargs):
        assert urlsplit(url).scheme == "https", "Credential transport must be HTTPS"
        assert "verify" not in kwargs and "allow_redirects" not in kwargs
        return self.session.request(method, url, timeout=30, allow_redirects=False, **kwargs)

    def json(self, method, url, statuses=(200,), **kwargs):
        r = self.request(method, url, **kwargs)
        assert r.status_code in statuses, (r.status_code, r.text)
        return r.json() if r.content else None


def host(container, hostname):
    obj = json.loads(run("docker", "inspect", container))[0]
    address = obj["NetworkSettings"]["Networks"][NETWORK]["IPAddress"]
    current = Path("/etc/hosts").read_text()
    line = f"{address} {hostname} # idp-bakeoff\n"
    run("sudo", "tee", "/etc/hosts", input=current + line)
    return address


def decode(token):
    parts = token.split(".")
    assert len(parts) == 3
    return [json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))) for p in parts[:2]]


def challenge():
    verifier = secret(secrets.token_urlsafe(48))
    value = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    return verifier, value


def cleanup():
    global SECRETS
    OUT.mkdir(parents=True, exist_ok=True)
    inventory = WORK / "secrets.json"
    if inventory.exists():
        SECRETS = json.loads(inventory.read_text())
    ids = run("docker", "ps", "-aq", "--filter", "label=datopsis.idp-bakeoff=true").split()
    for cid in ids:
        obj = json.loads(run("docker", "inspect", cid))[0]
        log = subprocess.run(["docker", "logs", cid], capture_output=True, text=True)
        save(obj["Name"].strip("/") + ".log.json", {"log": log.stdout + log.stderr})
        run("docker", "rm", "-fv", cid)
    networks = run("docker", "network", "ls", "-q", "--filter", "name=^idp-bakeoff$").split()
    for network in networks:
        run("docker", "network", "rm", network)
    current = Path("/etc/hosts").read_text()
    run(
        "sudo",
        "tee",
        "/etc/hosts",
        input="".join(
            line
            for line in current.splitlines(keepends=True)
            if not line.endswith(" # idp-bakeoff\n")
        ),
    )
    # Recheck all allowlisted evidence, including exception strings, before upload.
    for path in OUT.glob("*"):
        if path.is_file():
            path.write_text(clean(path.read_text()))
    (OUT / "SANITIZED").write_text("Redaction and container cleanup completed.\n")


if __name__ == "__main__":
    cleanup()
