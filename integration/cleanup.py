"""Collect diagnostics, then publish only redacted files. Fail closed on sanitizing errors."""

import json
import re
import shutil
import subprocess
from pathlib import Path

from gates import redact

ROOT = Path(__file__).resolve().parents[1]


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
        dc = ["docker", "compose", "-f", str(ROOT / "integration/compose.yaml")]
        logs = subprocess.run(
            dc + ["logs", "--no-color"], text=True, capture_output=True, check=False
        )
        (reports / "services.log").write_text(logs.stdout + logs.stderr)
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
                text = redact(path.read_text(), values)
                assert not any(value and value in text for value in values)
                (safe / path.name).write_text(text)
    except Exception:
        shutil.rmtree(safe)
        raise
    # The upload step additionally requires this step to succeed.
    assert not teardown_failed, "Compose teardown failed; inspect local reports/teardown.log"


if __name__ == "__main__":
    main()
