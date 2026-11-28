"""Always-run recovery for interrupted T13 jobs; fail closed before artifact upload."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if (ROOT / ".runtime/idp").exists():
    sys.path.insert(0, str(ROOT / "evaluation/idp"))
    import common
    from auth_fixture import cleanup

    common.OUT = ROOT / "reports/t13/interrupted"
    cleanup(common)

# Child processes and their tee writers have exited before this always-run step.
# Retain every suite's inventory until this final pass, including any traceback
# appended after an individual suite's finally block.
from auth_redact import redact_reports, retain  # noqa: E402

inventory = ROOT / ".runtime/t13-secrets.json"
values = retain(inventory) if inventory.exists() else []
redact_reports(ROOT / "reports", values)
if (ROOT / "reports/t13").exists():
    (ROOT / "reports/t13/SANITIZED").write_text("Final T13 redaction completed.\n")
inventory.unlink(missing_ok=True)
