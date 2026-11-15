"""Per-run test PKI for verified TLS. Uses OpenSSL only; nothing here is uploaded.

A fresh root signs every positive leaf. An unrelated root, correct-CN/wrong-SAN
leaves and backdated expired leaves are issued up front for the negative tests;
the signing keys are deleted once issuance is complete. Only public metadata
(fingerprints, SANs, validity) is ever recorded.
"""

import datetime as dt
import secrets
import shutil
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# Native TLS servers and proxies. Server identities are DNS SANs, never CN-only.
SERVERS = ("postgres", "catalog", "sail", "trino")
SEAWEED = ("master", "volume", "filer", "s3")
CLIENTS = tuple(role + "-client" for role in SEAWEED) + ("probe-client",)
# Relay/impostor targets: each gets a valid fixture leaf plus three mutations.
TARGETS = ("catalog", "s3", "trino", "sail", "postgres", "master", "filer")
VARIANTS = ("valid", "wrong-ca", "wrong-san", "expired")
WRONG_SAN = "wrong.invalid"


def openssl(*args):
    result = subprocess.run(["openssl", *map(str, args)], capture_output=True, text=True)
    if result.returncode:
        # OpenSSL diagnostics never contain private key bytes.
        raise RuntimeError("OpenSSL failed: " + " ".join(map(str, args[:2])) + result.stderr)
    return result.stdout


def stamp(moment):
    return moment.strftime("%Y%m%d%H%M%SZ")


def root(directory, name):
    """Self-signed root from an explicit config: exactly these extensions, no
    defaults from the system openssl.cnf (a duplicate extension voids the CA)."""
    config = directory / f"{name}.cnf"
    config.write_text(
        "[req]\ndistinguished_name=dn\nx509_extensions=root\nprompt=no\n"
        f"[dn]\nCN=lakehouse-integration {name}\n"
        "[root]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
        "subjectKeyIdentifier=hash\n"
    )
    openssl(
        "req",
        "-x509",
        "-config",
        config,
        "-newkey",
        "rsa:3072",
        "-nodes",
        "-sha256",
        "-days",
        "1",
        "-keyout",
        directory / f"{name}.key",
        "-out",
        directory / f"{name}.crt",
    )


def leaf(authority, output, name, cn, san, purpose, issuer="ca", expired=False):
    """Issue one RSA-3072/SHA-256 leaf with an isolated OpenSSL CA database."""
    now = dt.datetime.now(dt.timezone.utc)
    start, end = (
        (now - dt.timedelta(hours=2), now - dt.timedelta(hours=1))
        if expired
        else (now - dt.timedelta(minutes=5), now + dt.timedelta(hours=6))
    )
    with tempfile.TemporaryDirectory(dir=authority) as work:
        work = Path(work)
        key, csr = output / f"{name}.key", work / "leaf.csr"
        openssl(
            "req",
            "-new",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-sha256",
            "-subj",
            "/CN=" + cn,
            "-keyout",
            key,
            "-out",
            csr,
        )
        (work / "index").write_text("")
        (work / "serial").write_text(secrets.token_hex(16) + "\n")
        extensions = [
            "basicConstraints=critical,CA:FALSE",
            "keyUsage=critical,digitalSignature,keyEncipherment",
            "extendedKeyUsage=" + purpose,
        ]
        if san:
            extensions.append("subjectAltName=DNS:" + san)
        authority_path, work_path = Path(authority).as_posix(), work.as_posix()
        (work / "issue.cnf").write_text(
            f"[ca]\ndefault_ca=issuer\n[issuer]\ndatabase={work_path}/index\nserial={work_path}/serial\n"
            f"new_certs_dir={work_path}\ncertificate={authority_path}/{issuer}.crt\n"
            f"private_key={authority_path}/{issuer}.key\ndefault_md=sha256\npolicy=policy\n"
            "x509_extensions=leaf\n[policy]\ncommonName=supplied\n[leaf]\n"
            + "\n".join(extensions)
            + "\n"
        )
        openssl(
            "ca",
            "-batch",
            "-notext",
            "-config",
            work / "issue.cnf",
            "-in",
            csr,
            "-out",
            output / f"{name}.crt",
            "-startdate",
            stamp(start),
            "-enddate",
            stamp(end),
        )
    key.chmod(0o600)


def plan():
    """Every leaf: (file stem, CN, DNS SAN, extended key usage, issuer, expired)."""
    items = [(name, name, name, "serverAuth", "ca", False) for name in SERVERS]
    for role in SEAWEED:
        for protocol in ("http", "grpc"):
            items.append((f"{role}-{protocol}", role, role, "serverAuth", "ca", False))
    items += [(name, name, name, "clientAuth", "ca", False) for name in CLIENTS]
    # Client identity mutations for mTLS listeners.
    items.append(
        ("untrusted-client", "probe-client", "probe-client", "clientAuth", "unrelated", False)
    )
    items.append(("expired-client", "probe-client", "probe-client", "clientAuth", "ca", True))
    for target in TARGETS:
        items += [
            (f"{target}-valid", target, target, "serverAuth", "ca", False),
            (f"{target}-wrong-ca", target, target, "serverAuth", "unrelated", False),
            (f"{target}-wrong-san", target, WRONG_SAN, "serverAuth", "ca", False),
            (f"{target}-expired", target, target, "serverAuth", "ca", True),
        ]
    return items


def prepare(base):
    """Create base/authority (deleted keys) and base/leaves (runner-only, 0700)."""
    authority, leaves = base / "authority", base / "leaves"
    for directory in (base, authority, leaves):
        directory.mkdir(mode=0o700)
    root(authority, "ca")
    root(authority, "unrelated")
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(
            pool.map(
                lambda item: leaf(authority, leaves, item[0], item[1], item[2], item[3], *item[4:]),
                plan(),
            )
        )
    for issuer in ("ca", "unrelated"):
        (leaves / f"{issuer}.crt").write_bytes((authority / f"{issuer}.crt").read_bytes())
        (authority / f"{issuer}.key").unlink()  # No further issuance is possible.
    shutil.rmtree(authority)  # Also OpenSSL's per-issuance database leftovers.
    # Every non-expired leaf must outlive the job (no validity extension on failure).
    for name, *_, expired in plan():
        if not expired:
            openssl("x509", "-in", leaves / f"{name}.crt", "-checkend", "7200", "-noout")
    return leaves


def inventory(leaves):
    """Public certificate metadata only, for the sanitized evidence."""
    result = {}
    for path in sorted(leaves.glob("*.crt")):
        text = openssl(
            "x509",
            "-in",
            path,
            "-noout",
            "-subject",
            "-issuer",
            "-dates",
            "-fingerprint",
            "-sha256",
            "-ext",
            "subjectAltName,extendedKeyUsage",
        )
        result[path.stem] = [line.strip() for line in text.splitlines() if line.strip()]
    assert not any("PRIVATE KEY" in line for lines in result.values() for line in lines)
    return result
