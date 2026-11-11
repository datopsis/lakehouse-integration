"""Retain only redacted evidence; generated credentials never become artifacts."""
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
reports = root / 'reports'
reports.mkdir(exist_ok=True)
creds = root / '.runtime/credentials.json'
values = list(json.loads(creds.read_text()).values()) if creds.exists() else []

def redact(text):
    for value in values:
        text = text.replace(value, '[REDACTED]')
    return text

if creds.exists():
    dc = ['docker', 'compose', '-f', str(root / 'spike/compose.yaml')]
    logs = subprocess.run(dc + ['logs', '--no-color'], text=True, capture_output=True)
    (reports / 'services.log').write_text(redact(logs.stdout + logs.stderr))
    subprocess.run(dc + ['down', '--volumes', '--remove-orphans', '--timeout', '30'], check=False)
for path in reports.iterdir():
    if path.is_file():
        path.write_text(redact(path.read_text()))
