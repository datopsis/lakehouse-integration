"""Evaluation entry point; never imported by the required integration gate."""

import json
import os
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evaluation/idp"))
import common  # noqa: E402

common.OUT = ROOT / "reports/authz"
from common import save  # noqa: E402

INPUTS = json.loads((ROOT / "evaluation/authz/inputs.json").read_text())


def build():
    sys.path.insert(0, str(ROOT / "integration"))
    import build as owner
    from catalog import build_proxy

    arch = owner.native_architecture()
    results = {}
    for repo, pin in owner.PINS.items():
        if repo == "sail-ubi":
            continue
        results[repo] = owner.build(repo, pin, arch)
        save("builds.json", results)
        assert results[repo]["status"] == "pass", results[repo]
    results["nginx-ubi"] = build_proxy(arch, owner)
    save("builds.json", results)


def main():
    assert __debug__
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    assert arch == os.environ["INTEGRATION_ARCH"]
    from exercise import evaluate

    evaluate(arch)


if __name__ == "__main__":
    if sys.argv[1:] == ["build"]:
        build()
    elif sys.argv[1:] == ["cleanup"]:
        common.cleanup()
    else:
        main()
