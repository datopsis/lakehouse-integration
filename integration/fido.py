#!/usr/bin/env python3
"""CI-only FIDO cache key and full owner verification; never trust restored bytes."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".sources/rauthy-fido-verifier"
CACHE = ROOT / ".sources/fixture-inputs"


def locked_key(source):
    digests = [
        json.loads((source / f"artifacts/locks/{arch}.json").read_text())["downloads"]["fido-mds"][
            "sha256"
        ]
        for arch in ("amd64", "arm64")
    ]
    if digests[0] != digests[1] or not re.fullmatch("[0-9a-f]{64}", digests[0]):
        raise ValueError("Native FIDO locks must have the same valid SHA-256")
    return f"fido-mds-{digests[0]}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-key", action="store_true")
    args = parser.parse_args()
    revision = json.loads((ROOT / "images.lock.json").read_text())["rauthy-ubi"]
    if not re.fullmatch("[0-9a-f]{40}", revision):
        raise ValueError("Rauthy source must be pinned by full commit")
    if not SOURCE.exists():
        SOURCE.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            [
                "git",
                "clone",
                "--no-checkout",
                "https://github.com/datopsis/rauthy-ubi",
                str(SOURCE),
            ],
            stdout=sys.stderr,
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(SOURCE), "checkout", "--detach", revision],
            stdout=sys.stderr,
            check=True,
        )
    actual = subprocess.check_output(
        ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True
    ).strip()
    dirty = subprocess.check_output(["git", "-C", str(SOURCE), "status", "--porcelain"], text=True)
    if actual != revision or dirty:
        raise ValueError("Rauthy verifier differs from the approved source pin")
    key = locked_key(SOURCE)
    if args.cache_key:
        print(f"key={key}")
        return
    arch = os.environ.get("INTEGRATION_ARCH", "amd64")
    if arch not in ("amd64", "arm64"):
        raise ValueError("Unsupported native architecture")
    # The approved owner implementation hashes cached bytes, fetches fresh CRLs,
    # verifies signature, pinned-root path, validity/revocation, serial and
    # nextUpdate on EVERY invocation. No cached verification verdict is used.
    with tempfile.TemporaryDirectory(prefix="authz-fido-") as output:
        subprocess.run(
            [
                sys.executable,
                "scripts/artifacts.py",
                "acquire-fido",
                f"artifacts/locks/{arch}.json",
                "--output",
                output,
            ],
            cwd=SOURCE,
            env=dict(os.environ, FIDO_MDS_CACHE_DIR=str(CACHE)),
            check=True,
        )
    print("Locked Rauthy FIDO metadata fully verified; owner image build verifies it again.")


if __name__ == "__main__":
    main()
