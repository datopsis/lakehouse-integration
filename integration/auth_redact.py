"""Retain T13 redaction inventory until all subprocess output has settled."""

import json
import re
from pathlib import Path

from remote_signing import sanitize


def retain(path, values=()):
    """Union secret inventories across independent suites, failing on corruption."""
    path = Path(path)
    previous = json.loads(path.read_text()) if path.exists() else []
    assert isinstance(previous, list) and all(isinstance(value, str) for value in previous)
    values = list(values)
    assert all(isinstance(value, str) for value in values)
    combined = sorted(set(previous + values) - {""})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(combined) + "\n")
    path.chmod(0o600)
    return combined


def redact_reports(root, values):
    """Run after child processes/tee exit, including interrupted suite output."""
    root = Path(root)
    files = list(root.glob("t13*.log"))
    if (root / "t13").exists():
        files.extend(path for path in (root / "t13").rglob("*") if path.is_file())
    for path in files:
        text = sanitize(path.read_text(), values)
        text = re.sub(
            r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "[JWE]",
            text,
        )
        text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", "[JWT]", text)
        assert "PRIVATE KEY" not in text, f"Private key material in {path.name}"
        assert not any(value and value in text for value in values), path.name
        path.write_text(text)
