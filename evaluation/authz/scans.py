"""Information-only upstream OpenFGA image scans; Cedar CLI has no image here."""

import importlib.util
import json
import os
import platform
import subprocess

import run as entry
from common import OUT, ROOT, run, save

spec = importlib.util.spec_from_file_location("idp_scanners", ROOT / "evaluation/idp/scans.py")
scanners = importlib.util.module_from_spec(spec)
spec.loader.exec_module(scanners)


def main():
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    assert arch == os.environ["INTEGRATION_ARCH"]
    image = entry.INPUTS["openfga"]["image"]
    OUT.mkdir(parents=True, exist_ok=True)
    results = {}
    run("docker", "pull", "--platform", "linux/" + arch, image)
    assert run("docker", "image", "inspect", "--format", "{{.Architecture}}", image) == arch
    for name in ("trivy", "grype"):
        try:
            binary = scanners.install(name, arch)
            output = OUT / (name + "-openfga.json")
            args = (
                [
                    binary,
                    "image",
                    "--scanners",
                    "vuln",
                    "--format",
                    "json",
                    "--timeout",
                    "15m",
                    "--output",
                    str(output),
                    image,
                ]
                if name == "trivy"
                else [binary, "docker:" + image, "-o", "json", "--file", str(output)]
            )
            completed = subprocess.run(args, capture_output=True, text=True, timeout=900)
            assert completed.returncode == 0, completed.stdout + completed.stderr
            report = json.loads(output.read_text())
            results[name] = {
                "status": "complete",
                "fixable": scanners.counts(name, report),
                "scanner_version": scanners.TOOLS[name][1],
                "image": image,
                "architecture": arch,
            }
        except Exception as exc:
            results[name] = {"status": "error", "error": str(exc)}
        save("scans.json", results)
    assert all(r["status"] == "complete" for r in results.values()), results


if __name__ == "__main__":
    main()
