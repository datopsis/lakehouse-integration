"""Lay out per-service TLS material from the per-run PKI. Fail closed.

Each service directory holds only that service's own private files plus the
public CA. No container ever mounts .runtime/tls itself, the leaves directory or
another service's directory. Directories become root:0 0750 (public trust
0755), private files 0440 and public certificates 0444.
"""

import importlib.util
import json
import subprocess
from pathlib import Path

import pki

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".runtime"
TLS = RUNTIME / "tls"
SEAWEED_PROFILE = ROOT / ".sources/seaweedfs-ubi/scripts/lib/tls_profile.py"
# Owner-accepted interim residual risk (docs/DECISIONS.md, 2026-11-12/13): the
# S3 gateway's single outbound gRPC policy must list both identities it dials.
# Narrowest working setting; guarded by the exact-outcome canaries in tls_checks.
S3_OUTBOUND = "filer,master"
PROVISIONER_OUTBOUND = "master,filer"


def seaweed_profile():
    """The pinned seaweedfs-ubi (PR #81) role policy, imported, not copied."""
    spec = importlib.util.spec_from_file_location("seaweed_tls_profile", SEAWEED_PROFILE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def copy(source, target):
    target.write_bytes(source.read_bytes())


def seaweed_security(role, strict=False):
    profile = seaweed_profile()
    config = profile.security(role)
    if role == "s3" and not strict:
        config["grpc"]["client"]["allowed_server_commonNames"] = S3_OUTBOUND
        config["grpc"]["s3"]["allowed_server_commonNames"] = S3_OUTBOUND
    return profile.render(config), config


def seaweed_role(leaves, role, directory, strict=False):
    directory.mkdir()
    text, config = seaweed_security(role, strict)
    (directory / "security.toml").write_text(text)
    copy(leaves / "ca.crt", directory / "ca.crt")
    for protocol in ("grpc", "http"):
        for ext in ("crt", "key"):
            copy(leaves / f"{role}-{protocol}.{ext}", directory / f"{protocol}.{ext}")
    for ext in ("crt", "key"):
        copy(leaves / f"{role}-client.{ext}", directory / f"client.{ext}")
    return config


def provisioner(leaves, directory):
    """Administrative shell identity: CA, its own client leaf, nothing else."""
    directory.mkdir()
    config = {
        "tls": {"min_version": "TLS 1.2", "max_version": "TLS 1.3"},
        "grpc": {
            "ca": "/etc/seaweedfs/ca.crt",
            "client": {
                "cert": "/etc/seaweedfs/client.crt",
                "key": "/etc/seaweedfs/client.key",
                "allowed_server_commonNames": PROVISIONER_OUTBOUND,
            },
        },
        "https": {
            "client": {
                "enabled": True,
                "ca": "/etc/seaweedfs/ca.crt",
                "cert": "/etc/seaweedfs/client.crt",
                "key": "/etc/seaweedfs/client.key",
                "insecure_skip_verify": False,
            }
        },
    }
    (directory / "security.toml").write_text(seaweed_profile().render(config))
    copy(leaves / "ca.crt", directory / "ca.crt")
    for ext in ("crt", "key"):
        copy(leaves / f"probe-client.{ext}", directory / f"client.{ext}")
    return config


def trino(leaves, directory, password):
    directory.mkdir()
    (directory / "server.pem").write_bytes(
        (leaves / "trino.key").read_bytes() + (leaves / "trino.crt").read_bytes()
    )
    copy(leaves / "ca.crt", directory / "ca.crt")
    (directory / "truststore-password").write_text(password + "\n")
    # Build the PKCS12 truststore with the pinned image's own keytool, offline.
    work = RUNTIME / "keytool"
    work.mkdir(mode=0o777)
    work.chmod(0o777)
    copy(leaves / "ca.crt", work / "ca.crt")
    (work / "password").write_text(password + "\n")
    for path in work.iterdir():
        path.chmod(0o444)
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--network=none",
            "--entrypoint=/opt/java/bin/keytool",
            "-v",
            f"{work}:/work:rw",
            "localhost/trino-ubi:integration",
            "-importcert",
            "-noprompt",
            "-alias",
            "run-ca",
            "-file",
            "/work/ca.crt",
            "-keystore",
            "/work/trust.p12",
            "-storetype",
            "PKCS12",
            "-storepass:file",
            "/work/password",
        ],
        check=True,
        capture_output=True,
    )
    copy(work / "trust.p12", directory / "trust.p12")
    subprocess.run(["sudo", "rm", "-rf", str(work)], check=True)


def protect(directory, public=False):
    """root:0; private files 0440, certificates 0444 only where public."""
    files = [str(path) for path in directory.iterdir()]  # Before it becomes root-only.
    subprocess.run(["sudo", "chmod", "0444" if public else "0440", *files], check=True)
    subprocess.run(["sudo", "chown", "-R", "0:0", str(directory)], check=True)
    subprocess.run(["sudo", "chmod", "0755" if public else "0750", str(directory)], check=True)


def prepare(password):
    """Issue the run PKI and lay out every service directory. Returns evidence."""
    leaves = pki.prepare(RUNTIME / "pki")
    TLS.mkdir(mode=0o755)
    trust = TLS / "trust"
    trust.mkdir()
    copy(leaves / "ca.crt", trust / "ca.crt")
    for name, stem in (
        ("postgres", "postgres"),
        ("catalog-proxy", "catalog"),
        ("sail-proxy", "sail"),
    ):
        directory = TLS / name
        directory.mkdir()
        copy(leaves / f"{stem}.crt", directory / "server.crt")
        copy(leaves / f"{stem}.key", directory / "server.key")
    policies = {role: seaweed_role(leaves, role, TLS / role) for role in pki.SEAWEED}
    policies["s3-strict-canary"] = seaweed_role(leaves, "s3", TLS / "s3-strict-canary", True)
    policies["provisioner"] = provisioner(leaves, TLS / "provisioner")
    trino(leaves, TLS / "trino", password)
    for directory in [path for path in TLS.iterdir() if path != trust]:
        protect(directory)
    protect(trust, public=True)
    # Public certificates may be world-readable; private keys never.
    for name in ("postgres", "catalog-proxy", "sail-proxy"):
        subprocess.run(["sudo", "chmod", "0444", str(TLS / name / "server.crt")], check=True)
    subprocess.run(["sudo", "chmod", "0755", str(TLS)], check=True)
    return {
        "certificates": pki.inventory(leaves),
        "seaweed_policies": json.loads(json.dumps(policies)),
    }


def install(source, target, mode="0440"):
    """Replace one fixture file in a root-owned directory (negative tests)."""
    subprocess.run(
        ["sudo", "install", "-o", "0", "-g", "0", "-m", mode, str(source), str(target)], check=True
    )


def remove():
    for path in (TLS, RUNTIME / "pki", RUNTIME / "keytool", RUNTIME / "relay"):
        subprocess.run(["sudo", "rm", "-rf", str(path)], check=True)
