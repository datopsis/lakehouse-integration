#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -c 'import sys; sys.path.insert(0, "integration"); from build import native_architecture; print("Native architecture:", native_architecture())'
mkdir -p reports
trap 'python3 integration/cleanup.py' EXIT
python3 integration/build.py 2>&1 | tee reports/build.log
status=0
python3 integration/verify.py 2>&1 | tee reports/provenance.log || status=1
.venv/bin/python integration/probe.py 2>&1 | tee reports/probe.log || status=1
exit "$status"
