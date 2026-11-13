"""Official Cedar CLI policy-point prototype, NOT a Lakekeeper/Trino integration."""

import hashlib
import json
import subprocess
import tarfile
import time
import urllib.request

from common import ROOT, WORK, decode, run, write


def evaluate(arch, catalog, token):
    # Lakekeeper's real OIDC verifier authenticates the unmodified Rauthy JWT.
    # Decoding alone is never treated as authentication for this prototype.
    identity = catalog.http.json(
        "GET", catalog.base + "/management/v1/whoami", headers={"Authorization": "Bearer " + token}
    )
    claims = decode(token)[1]
    assert "lake-readers" in claims["groups"]
    spec = json.loads((ROOT / "evaluation/authz/inputs.json").read_text())["cedar"]
    pin = spec["archives"][arch]
    directory = WORK / "cedar"
    directory.mkdir()
    archive = directory / "cli.tar.xz"
    urllib.request.urlretrieve(
        "https://github.com/cedar-policy/cedar/releases/download/"
        + spec["release"]
        + "/cedar-policy-cli-"
        + pin["target"]
        + ".tar.xz",
        archive,
    )
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == pin["sha256"]
    binary = directory / "cedar"
    with tarfile.open(archive) as tar:
        source = tar.extractfile("cedar-policy-cli-" + pin["target"] + "/cedar")
        binary.write_bytes(source.read())
    binary.chmod(0o755)
    version = run(binary, "--version")
    assert spec["version"] in version
    policy = directory / "policy.cedar"
    write(
        policy,
        'permit(principal in Group::"lake-readers", action in [Action::"list", Action::"read"], resource in Namespace::"bakeoff");\n',
    )
    user = {"type": "User", "id": claims["iss"] + "|" + claims["sub"]}
    entities = [
        {
            "uid": user,
            "attrs": {},
            "parents": [{"type": "Group", "id": g} for g in claims["groups"]],
        }
    ]
    for ns in ("bakeoff", "denied"):
        entities.append(
            {
                "uid": {"type": "Table", "id": ns + ".sample"},
                "attrs": {},
                "parents": [{"type": "Namespace", "id": ns}],
            }
        )
    write(directory / "entities.json", entities)
    decisions = {}

    def check(action, namespace, expected):
        request = {
            "principal": user,
            "action": {"type": "Action", "id": action},
            "resource": {"type": "Table", "id": namespace + ".sample"},
            "context": {},
        }
        write(directory / "request.json", request)
        start = time.monotonic()
        result = subprocess.run(
            [
                str(binary),
                "authorize",
                "--policies",
                str(policy),
                "--entities",
                str(directory / "entities.json"),
                "--request-json",
                str(directory / "request.json"),
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode in (0, 2), (result.returncode, result.stdout, result.stderr)
        assert result.stdout.strip() == expected, (result.stdout, result.stderr)
        return {"decision": expected, "process_wall_seconds": time.monotonic() - start}

    for action, ns, expected in (
        ("list", "bakeoff", "ALLOW"),
        ("read", "bakeoff", "ALLOW"),
        ("write", "bakeoff", "DENY"),
        ("read", "denied", "DENY"),
    ):
        decisions[action + "/" + ns] = check(action, ns, expected)
    write(policy, "// grant revoked\n")
    decisions["revoke"] = check("read", "bakeoff", "DENY")
    return {
        "version": version,
        "binary_bytes": binary.stat().st_size,
        "decisions": decisions,
        "verified_identity": identity,
        "groups": claims["groups"],
        "scope": "Standalone CLI; no Lakekeeper or Trino enforcement, no hosted service",
    }
