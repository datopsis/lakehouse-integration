"""Information-only upstream image findings. Scanner errors are never zero findings."""

import hashlib
import json
import os
import platform
import subprocess
import tarfile
import urllib.request

from common import OUT, WORK, run, save
from providers import IMAGES

TOOLS = {
    "trivy": (
        "aquasecurity/trivy",
        "0.76.2",
        {
            "amd64": (
                "Linux-64bit",
                "bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf",
            ),
            "arm64": (
                "Linux-ARM64",
                "ab9d51f86e6a5fb936f605faff6b593ac51bc378fff4d3e8b9d58358b9c367c3",
            ),
        },
    ),
    "grype": (
        "anchore/grype",
        "0.121.3",
        {
            "amd64": (
                "linux_amd64",
                "e9da18cc1429e786722e32161288103600efffd8e483c90761f90485bd1bec85",
            ),
            "arm64": (
                "linux_arm64",
                "b7815598d48da78bfd16f5b98ef28e1bb09c03d34fc8c3e350f99b6ccb3c7cba",
            ),
        },
    ),
}


def install(name, arch):
    repo, version, variants = TOOLS[name]
    suffix, sha = variants[arch]
    directory = WORK / "tools"
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f"{name}.tar.gz"
    url = f"https://github.com/{repo}/releases/download/v{version}/{name}_{version}_{suffix}.tar.gz"
    urllib.request.urlretrieve(url, archive)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == sha
    with tarfile.open(archive) as tar:
        member = tar.extractfile(name)
        assert member
        binary = directory / name
        binary.write_bytes(member.read())
        binary.chmod(0o755)
    archive.unlink()
    return str(binary)


def counts(scanner, report):
    found = set()
    if scanner == "trivy":
        for target in report.get("Results", []):
            for v in target.get("Vulnerabilities", []):
                if v["Severity"] in ("HIGH", "CRITICAL") and v.get("FixedVersion"):
                    found.add(
                        (
                            v["Severity"],
                            target["Target"],
                            v["PkgName"],
                            v["InstalledVersion"],
                            v["VulnerabilityID"],
                        )
                    )
    else:
        for match in report["matches"]:
            v, pkg = match["vulnerability"], match["artifact"]
            if v["severity"] in ("High", "Critical") and v.get("fix", {}).get("state") == "fixed":
                found.add(
                    (
                        v["severity"].upper(),
                        pkg.get("purl", pkg["name"]),
                        pkg["name"],
                        pkg["version"],
                        v["id"],
                    )
                )
    return {s: sum(row[0] == s for row in found) for s in ("HIGH", "CRITICAL")}


def main():
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    assert arch == os.environ["INTEGRATION_ARCH"]
    OUT.mkdir(parents=True, exist_ok=True)
    results = {}
    for name in ("trivy", "grype"):
        try:
            binary = install(name, arch)
        except Exception as exc:
            results[name] = {"status": "error", "error": str(exc)}
            save("scans.json", results)
            continue
        for provider, image in IMAGES.items():
            key = name + "/" + provider
            try:
                run("docker", "pull", "--platform", "linux/" + arch, image)
                assert (
                    run("docker", "image", "inspect", "--format", "{{.Architecture}}", image)
                    == arch
                )
                output = OUT / f"{name}-{provider}.json"
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
                results[key] = {
                    "status": "complete",
                    "fixable": counts(name, report),
                    "image": image,
                    "architecture": arch,
                    "scanner_version": TOOLS[name][1],
                    "version_output": run(binary, "--version"),
                }
            except Exception as exc:
                results[key] = {"status": "error", "error": str(exc)}
            save("scans.json", results)
    assert len(results) == 6 and all(r["status"] == "complete" for r in results.values()), results


if __name__ == "__main__":
    main()
