"""Compose pinned slice 4a acceptance helpers with this repo's TLS/storage pins.

No owner checkout is edited. Runtime entry points require a disposable Actions job.
"""

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".sources/datopsis-authz"
PINS = json.loads((ROOT / "images.lock.json").read_text())


def load(suite):
    import subprocess

    assert os.environ.get("GITHUB_ACTIONS") == "true", "T13 runtime is CI-only"
    assert (
        subprocess.check_output(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True).strip()
        == PINS["datopsis-authz"]
    )
    assert not subprocess.check_output(
        ["git", "-C", str(SOURCE), "diff", "HEAD"], text=True
    ).strip()
    sys.path.extend(
        str(path)
        for path in (
            SOURCE / "evaluation/s1",
            SOURCE / "evaluation/s2",
            ROOT / "evaluation/authz",
            ROOT / "evaluation/idp",
        )
    )
    import catalog
    import common
    import fixture
    import rauthy

    common.OUT = ROOT / "reports/t13" / suite
    rauthy.REVISION = PINS["rauthy-ubi"]
    rauthy.IMAGE = "localhost/rauthy-ubi:integration"
    catalog.PROXY_IMAGE = "localhost/nginx-ubi:integration"
    original = fixture.container

    def hardened(name, image, *args, **kwargs):
        # Reuse the existing reviewed PostgreSQL image for a separate authz DB.
        if image == "localhost/postgresql-ubi:integration":
            image = "localhost/postgresql-lakekeeper-ubi:integration"
        extra = list(kwargs.get("extra", ()))
        if name in ("master", "volume", "filer"):
            # A read-only root still needs a private writable data volume.
            # Anonymous volumes are removed by the fixture's docker rm -fv.
            extra += ["--volume", "/data"]
        for option in ("--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true"):
            if not any(str(item).split(":")[0] == option.split(":")[0] for item in extra):
                extra.append(option)
        if not any(str(item).startswith("/tmp:") for item in extra):
            extra += ["--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"]
        kwargs["extra"] = extra
        return original(name, image, *args, **kwargs)

    fixture.container = hardened
    import s1_fixture

    return common, s1_fixture


def cleanup(common):
    from auth_redact import redact_reports, retain

    values = list(common.SECRETS)
    inventory = common.WORK / "secrets.json"
    if inventory.exists():
        stored = json.loads(inventory.read_text())
        assert isinstance(stored, list) and all(isinstance(value, str) for value in stored)
        values.extend(stored)
    values = retain(ROOT / ".runtime/t13-secrets.json", values)
    common.cleanup()
    for network in common.run(
        "docker", "network", "ls", "-q", "--filter", "name=^(authz-backend|slice1-idp)$"
    ).split():
        common.run("docker", "network", "rm", network)
    redact_reports(ROOT / "reports", values, include_root_logs=False)
    common.run("sudo", "rm", "-rf", common.WORK)
