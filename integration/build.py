"""Acquire pinned sources and invoke repository-owned builds without editing them."""

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
REPORTS.mkdir(exist_ok=True)
PINS = json.loads((ROOT / "images.lock.json").read_text())


def run(args, **kwargs):
    print("+", " ".join(map(str, args)), flush=True)
    return subprocess.run(args, check=True, **kwargs)


def output(args):
    return subprocess.check_output(args, text=True).strip()


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(repo, revision):
    source = ROOT / ".sources" / repo
    source.mkdir(parents=True)
    run(["git", "init", "-q", str(source)])
    run(
        [
            "git",
            "-C",
            str(source),
            "remote",
            "add",
            "origin",
            f"https://github.com/datopsis/{repo}.git",
        ]
    )
    fetched = subprocess.run(["git", "-C", str(source), "fetch", "--depth=1", "origin", revision])
    if fetched.returncode:
        assert repo == "trino-ubi", "Exact SHA fetch failed"
        run(["git", "-C", str(source), "fetch", "--depth=1", "origin", "refs/pull/2/head"])
    run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"])
    assert output(["git", "-C", str(source), "rev-parse", "HEAD"]) == revision
    assert not output(["git", "-C", str(source), "status", "--porcelain"])
    image = f"localhost/{repo}:integration"
    runtime = "podman" if repo in ("lakekeeper-ubi", "seaweedfs-ubi") else "docker"
    env = dict(os.environ, CONTAINER_RUNTIME=runtime, IMAGE=image, RELEASE_REVISION=revision)
    if repo == "postgresql-lakekeeper-ubi":
        command = ["bash", "scripts/build-offline.sh"]
        lock = source / "artifacts/locks/amd64.json"
    elif repo == "lakekeeper-ubi":
        command = [
            "bash",
            "scripts/build.sh",
            "--arch",
            "amd64",
            "--runtime",
            runtime,
            "--tag",
            image,
        ]
        lock = source / "artifacts/lakekeeper.lock.json"
    elif repo == "seaweedfs-ubi":
        # Extract (never run) the exact verifier image chosen by the owner's script.
        # Host execution avoids an unhardened helper container and leaves admission intact.
        ref = "ghcr.io/sigstore/cosign/cosign@sha256:68839b7f13dac5a6744a5d8818e984dd39183374e37855c19e14d623d9bc9037"
        run(["docker", "pull", ref])
        cid = output(["docker", "create", ref])
        verifier = ROOT / ".sources/cosign"
        try:
            run(["docker", "cp", f"{cid}:/ko-app/cosign", str(verifier)])
        finally:
            run(["docker", "rm", cid])
        verifier.chmod(0o755)
        env["COSIGN"] = str(verifier)
        command = ["bash", "scripts/build.sh", "amd64"]
        lock = source / "artifacts/seaweedfs.lock.json"
    elif repo == "sail-ubi":
        from sail_build import prepare_build

        command = prepare_build(source, env, run)
        lock = source / "artifacts/sail.lock.json"
    else:
        command = ["bash", "scripts/build.sh", "amd64"]
        lock = source / "artifacts/trino.lock.json"
    run(command, cwd=source, env=env)
    if runtime == "podman":
        archive = ROOT / ".sources/transfer.tar"
        run(["podman", "save", "--format", "docker-archive", "-o", str(archive), image])
        run(["docker", "load", "-i", str(archive)])
        archive.unlink()
    inspected = json.loads(output(["docker", "image", "inspect", image]))[0]
    labels = inspected["Config"].get("Labels") or {}
    result = {
        "revision": revision,
        "image_id": inspected["Id"],
        "architecture": inspected["Architecture"],
        "lock_sha256": sha(lock),
        "labels": labels,
    }
    if repo == "sail-ubi":
        from sail_build import lock_evidence

        result.update(lock_evidence(source))
    result["provenance_errors"] = provenance_errors(inspected, revision, result["lock_sha256"])
    result["status"] = "fail" if result["provenance_errors"] else "pass"
    # Preserve the spike's binary checks as additional evidence, never as a
    # substitute for the strict revision and artifact-lock labels.
    if repo in ("lakekeeper-ubi", "seaweedfs-ubi"):
        binary = "lakekeeper" if repo == "lakekeeper-ubi" else "weed"
        container = output(["docker", "create", image])
        extracted = ROOT / ".sources" / f"{binary}-from-image"
        try:
            run(["docker", "cp", f"{container}:/usr/local/bin/{binary}", str(extracted)])
            result["image_binary_sha256"] = sha(extracted)
            artifact = json.loads(lock.read_text())
            assert (
                result["image_binary_sha256"]
                == artifact["architectures"]["amd64"]["binary"]["sha256"]
            )
            if repo == "seaweedfs-ubi":
                assert (
                    labels["io.datopsis.seaweedfs.commit"] == artifact["upstream"]["releaseCommit"]
                )
        finally:
            run(["docker", "rm", container])
            extracted.unlink(missing_ok=True)
    assert not output(["git", "-C", str(source), "diff", "HEAD"])
    return result


def provenance_errors(inspected, revision, lock_hash):
    errors = []
    if inspected["Architecture"] != "amd64":
        errors.append("image architecture is not amd64")
    labels = inspected["Config"].get("Labels") or {}
    for key, expected in [
        ("org.opencontainers.image.revision", revision),
        ("io.datopsis.artifact-lock.sha256", lock_hash),
    ]:
        if labels.get(key) != expected:
            errors.append(f"{key}: expected {expected}, got {labels.get(key)!r}")
    return errors


def main():
    if not __debug__:
        raise RuntimeError("Assertions must be enabled; remove -O/PYTHONOPTIMIZE")
    assert len(PINS) == 5 and all(re.fullmatch(r"[0-9a-f]{40}", pin) for pin in PINS.values())
    results = {}
    for repo, revision in PINS.items():
        start = time.monotonic()
        try:
            results[repo] = build(repo, revision)
        except Exception as exc:
            results[repo] = {"status": "build-failed", "error": str(exc)}
            import traceback

            traceback.print_exc()
        results[repo]["seconds"] = round(time.monotonic() - start, 2)
        (REPORTS / "builds.json").write_text(json.dumps(results, indent=2) + "\n")
    # Provenance is a separate mandatory gate, allowing runtime diagnostics even
    # when a built image fails its labels. No provenance failure becomes a pass.
    assert all(r["status"] != "build-failed" for r in results.values()), results


if __name__ == "__main__":
    main()
