"""Collect diagnostics, then publish only redacted files. Fail closed on sanitizing errors."""

import json
import re
import shutil
import subprocess
from pathlib import Path

from remote_signing import sanitize

ROOT = Path(__file__).resolve().parents[1]
# One-off TLS fixtures (relay, probe engines, impostors, canaries) outside Compose.
ONE_OFF = (
    "lakehouse-integration-tls-relay",
    "lakehouse-integration-trino-probe",
    "lakehouse-integration-sail-probe",
    "lakehouse-integration-catalog-probe",
    "lakehouse-integration-postgres-impostor",
    "lakehouse-integration-migrate-probe",
    "lakehouse-integration-weed-client",
    "lakehouse-integration-s3-strict-canary",
    "lakehouse-integration-provisioner",
)


def main():
    reports = ROOT / "reports"
    reports.mkdir(exist_ok=True)
    safe = reports / "sanitized"
    if safe.exists():
        shutil.rmtree(safe)
    creds = ROOT / ".runtime/credentials.json"
    assert not (ROOT / ".runtime").exists() or creds.exists(), "Missing redaction inventory"
    values = list(json.loads(creds.read_text()).values()) if creds.exists() else []
    teardown_failed = False
    if creds.exists():
        dc = [
            "docker",
            "compose",
            "-f",
            str(ROOT / "integration/compose.yaml"),
            "-f",
            str(ROOT / "integration/compose.sail.yaml"),
        ]
        logs = subprocess.run(
            dc + ["logs", "--no-color"], text=True, capture_output=True, check=False
        )
        (reports / "services.log").write_text(logs.stdout + logs.stderr)
        for name in ONE_OFF:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=False)
        result = subprocess.run(
            dc + ["down", "--volumes", "--remove-orphans", "--timeout", "30"],
            text=True,
            capture_output=True,
            check=False,
        )
        (reports / "teardown.log").write_text(result.stdout + result.stderr)
        teardown_failed = result.returncode != 0
    hosts = Path("/etc/hosts").read_text()
    cleaned = re.sub(
        r"# lakehouse-integration-start\n.*?# lakehouse-integration-end\n", "", hosts, flags=re.S
    )
    if hosts != cleaned:
        subprocess.run(
            ["sudo", "tee", "/etc/hosts"],
            input=cleaned,
            text=True,
            stdout=subprocess.DEVNULL,
            check=True,
        )
    safe.mkdir()
    try:
        for path in reports.iterdir():
            if path.is_file():
                text = sanitize(path.read_text(), values)
                assert not any(value and value in text for value in values)
                # Private key material must never reach an artifact.
                assert "PRIVATE KEY" not in text, f"PEM private key material in {path.name}"
                (safe / path.name).write_text(text)
    except Exception:
        shutil.rmtree(safe)
        raise
    # Per-run PKI and service TLS material never outlive the job, even on failure.
    for name in ("tls", "pki", "relay", "pg-impostor", "keytool"):
        subprocess.run(["sudo", "rm", "-rf", str(ROOT / ".runtime" / name)], check=True)
    # The upload step additionally requires this step to succeed.
    assert not teardown_failed, "Compose teardown failed; inspect local reports/teardown.log"


if __name__ == "__main__":
    main()
