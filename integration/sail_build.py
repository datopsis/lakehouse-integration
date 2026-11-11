"""Sail's owner build and isolated, owner hash-locked Spark Connect client."""

import hashlib
import os
from pathlib import Path


def prepare_build(source, env, run):
    # Keep Sail's client Arrow separate from the integration's decoder canary.
    venv = source.parent / "sail-venv"
    run(["python3", "-m", "venv", str(venv)])
    python = str(venv / "bin/python")
    run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--only-binary=:all:",
            "-r",
            str(source / ".github/requirements/ci.txt"),
        ]
    )
    run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "--no-build-isolation",
            "-r",
            str(source / ".github/requirements/client.txt"),
        ]
    )
    env.update(PATH=str(venv / "bin") + os.pathsep + env["PATH"], ARCHITECTURE="amd64")
    return ["bash", "scripts/build.sh"]


def lock_evidence(source):
    # Exactly scripts/build.sh's contract: cat sail.lock.json rpms.lock.json | sha256sum.
    paths = [Path("artifacts/sail.lock.json"), Path("artifacts/rpms.lock.json")]
    return {
        "lock_sha256": hashlib.sha256(
            b"".join((source / p).read_bytes() for p in paths)
        ).hexdigest(),
        "lock_inputs": {
            str(p): hashlib.sha256((source / p).read_bytes()).hexdigest() for p in paths
        },
    }
