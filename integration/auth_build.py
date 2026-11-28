"""CI-only owner builds for T13. Never alter owner source, labels or gates."""

import json
import os
from pathlib import Path

from build import output, provenance_errors, run, sha


def rauthy(source, env, architecture):
    # The owner verifies hash, signature, chain, fresh CRLs, serial and dates,
    # including cache hits. Its build performs the verification again.
    env["FIDO_MDS_CACHE_DIR"] = str(source.parent / "fixture-inputs")
    env["TEST_IMAGE"] = env["IMAGE"]
    return ["bash", "scripts/build.sh"]


def authz(source, revision, architecture):
    lock = source / "artifacts/images.lock.json"
    run(["python3", "scripts/image-inputs.py", architecture], cwd=source)
    # Parse the owner-generated env as data; never eval shell from a subprocess.
    values = {}
    for line in (source / ".image-bundle/build.env").read_text().splitlines():
        if line.startswith(("BUILDER=", "RUNTIME=")):
            key, value = line.split("=", 1)
            values[key] = value.strip("'\"")
    assert set(values) == {"BUILDER", "RUNTIME"}, values.keys()
    images = {}
    for name in ("authz", "lakekeeper-authz"):
        image = f"localhost/{name}:integration"
        run(
            [
                "docker",
                "build",
                "-f",
                "Containerfile",
                "--target",
                name,
                "-t",
                image,
                "--build-arg",
                "BUILDER=" + values["BUILDER"],
                "--build-arg",
                "RUNTIME=" + values["RUNTIME"],
                "--build-arg",
                "SOURCE_REVISION=" + revision,
                "--build-arg",
                "LOCK_SHA256=" + sha(lock),
                ".",
            ],
            cwd=source,
            env=dict(os.environ, CARGO_BUILD_JOBS="2"),
        )
        obj = json.loads(output(["docker", "image", "inspect", image]))[0]
        errors = provenance_errors(obj, revision, sha(lock), architecture)
        images[name] = {
            "status": "fail" if errors else "pass",
            "revision": revision,
            "image_id": obj["Id"],
            "architecture": obj["Architecture"],
            "lock_sha256": sha(lock),
            "labels": obj["Config"].get("Labels", {}),
            "provenance_errors": errors,
        }
    # Exact image aliases expected by the pinned acceptance helpers. No layers.
    for name, alias in (("authz", "authz-serve"), ("lakekeeper-authz", "lakekeeper-datopsis")):
        run(["docker", "tag", f"localhost/{name}:integration", f"localhost/{alias}:s1"])
    assert not output(["git", "-C", str(source), "diff", "HEAD"])
    return {
        "status": "pass" if all(i["status"] == "pass" for i in images.values()) else "fail",
        "revision": revision,
        "architecture": architecture,
        "expected_architecture": architecture,
        "lock_path": str(Path("artifacts/images.lock.json")),
        "lock_sha256": sha(lock),
        "images": images,
        "provenance_errors": [e for i in images.values() for e in i["provenance_errors"]],
    }
