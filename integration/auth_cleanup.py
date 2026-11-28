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
