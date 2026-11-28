"""Immutable native CI image cache; every restored image repeats strict provenance."""

import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGES = {
    "rauthy-ubi": ["localhost/rauthy-ubi:integration"],
    "datopsis-authz": ["localhost/authz:integration", "localhost/lakekeeper-authz:integration"],
}


def recipe_hash():
    return hashlib.sha256(
        b"".join(
            (ROOT / "integration" / name).read_bytes()
            for name in (
                "build.py",
                "auth_build.py",
                "image_cache.py",
                "fido.py",
            )
        )
    ).hexdigest()


def validate(manifest, repo, revision, architecture, lock_hash):
    assert manifest["schema"] == 1
    assert manifest["repo"] == repo and manifest["revision"] == revision
    assert manifest["architecture"] == architecture
    assert manifest["lock_sha256"] == lock_hash
    assert manifest["recipe_sha256"] == recipe_hash()
    assert re.fullmatch(r"[0-9a-f]{64}", manifest["archive_sha256"])
    assert set(manifest["images"]) == set(IMAGES[repo])
    assert all(re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in manifest["images"].values())


def validate_archive(archive, expected):
    """A restored archive cannot replace unrelated tags built earlier in the job."""
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember("manifest.json")
        assert member.size < 1024 * 1024
        records = json.load(bundle.extractfile(member))
        actual = {}
        for record in records:
            config = bundle.getmember(record["Config"])
            assert config.size < 1024 * 1024
            digest = "sha256:" + hashlib.sha256(bundle.extractfile(config).read()).hexdigest()
            assert record["RepoTags"] and set(record["RepoTags"]).isdisjoint(actual)
            actual.update(dict.fromkeys(record["RepoTags"], digest))
        assert actual == expected, "Unexpected tags or config digests in cached image archive"


def restore(source, repo, revision, architecture):
    if os.environ.get("CI_IMAGE_CACHE") != "true" or repo not in IMAGES:
        return None
    directory = ROOT / ".image-cache" / repo
    if not directory.exists():
        return None
    from build import artifact_lock, output, provenance_errors, run, sha

    lock = artifact_lock(source, repo, architecture)
    manifest = json.loads((directory / "manifest.json").read_text())
    validate(manifest, repo, revision, architecture, sha(lock))
    archive = directory / "images.tar.gz"
    assert sha(archive) == manifest["archive_sha256"]
    validate_archive(archive, manifest["images"])
    run(["docker", "load", "-i", str(archive)])
    inspected = {}
    for image in IMAGES[repo]:
        obj = json.loads(output(["docker", "image", "inspect", image]))[0]
        assert obj["Id"] == manifest["images"][image]
        errors = provenance_errors(obj, revision, sha(lock), architecture)
        assert not errors, errors  # Corrupt caches fail; no fallback or label allowance.
        inspected[image] = {
            "status": "pass",
            "revision": revision,
            "image_id": obj["Id"],
            "architecture": obj["Architecture"],
            "lock_sha256": sha(lock),
            "labels": obj["Config"].get("Labels", {}),
            "provenance_errors": errors,
        }
    result = {
        "status": "pass",
        "revision": revision,
        "architecture": architecture,
        "expected_architecture": architecture,
        "lock_path": str(lock.relative_to(source)),
        "lock_sha256": sha(lock),
        "provenance_errors": [],
        "cache": {
            "hit": True,
            "archive_sha256": manifest["archive_sha256"],
            "recipe_sha256": recipe_hash(),
        },
    }
    if repo == "datopsis-authz":
        result["images"] = {
            name: inspected[f"localhost/{name}:integration"]
            for name in ("authz", "lakekeeper-authz")
        }
        for name, alias in (("authz", "authz-serve"), ("lakekeeper-authz", "lakekeeper-datopsis")):
            run(["docker", "tag", f"localhost/{name}:integration", f"localhost/{alias}:s1"])
    else:
        result.update(inspected[IMAGES[repo][0]])
    return result


def save(source, repo, revision, architecture, result):
    if os.environ.get("CI_IMAGE_CACHE") != "true" or repo not in IMAGES:
        return
    assert result["status"] == "pass" and not result["provenance_errors"]
    from build import artifact_lock, output, sha

    directory = ROOT / ".image-cache" / repo
    directory.mkdir(parents=True)  # A restored but invalid cache must never be overwritten.
    archive = directory / "images.tar.gz"
    process = subprocess.Popen(["docker", "save", *IMAGES[repo]], stdout=subprocess.PIPE)
    try:
        with gzip.open(archive, "wb", compresslevel=1) as target:
            shutil.copyfileobj(process.stdout, target)
    finally:
        process.stdout.close()
        assert process.wait() == 0, "Native image export failed"
    images = {
        image: json.loads(output(["docker", "image", "inspect", image]))[0]["Id"]
        for image in IMAGES[repo]
    }
    validate_archive(archive, images)
    manifest = {
        "schema": 1,
        "repo": repo,
        "revision": revision,
        "architecture": architecture,
        "lock_sha256": sha(artifact_lock(source, repo, architecture)),
        "recipe_sha256": recipe_hash(),
        "archive_sha256": sha(archive),
        "images": images,
    }
    (directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    result["cache"] = {
        "hit": False,
        "archive_sha256": manifest["archive_sha256"],
        "recipe_sha256": recipe_hash(),
    }


if __name__ == "__main__":
    from build import PINS, native_architecture

    assert __debug__
    architecture = native_architecture()
    for output_name, repo in (("rauthy", "rauthy-ubi"), ("authz", "datopsis-authz")):
        print(f"{output_name}=native-image-v1-{architecture}-{repo}-{PINS[repo]}-{recipe_hash()}")
