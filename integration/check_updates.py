"""Read-only upstream main comparison. Never change a pin or create a PR."""

import json
import os
import urllib.request
from pathlib import Path


def github(path):
    request = urllib.request.Request(
        "https://api.github.com/" + path,
        headers={
            "Authorization": "Bearer " + os.environ["GH_TOKEN"],
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def main():
    pins = json.loads(Path("images.lock.json").read_text())
    lines = [
        "## Upstream main comparison",
        "",
        "| Repository | Pinned | main | Comparison |",
        "| --- | --- | --- | --- |",
    ]
    for repo, pin in pins.items():
        main = github(f"repos/datopsis/{repo}/commits/main")["sha"]
        comparison = github(f"repos/datopsis/{repo}/compare/{pin}...{main}")
        status = (
            f"{comparison['status']}; main has {comparison['ahead_by']} commits absent from pin"
        )
        lines.append(f"| {repo} | `{pin}` | `{main}` | {status} |")
    summary = "\n".join(lines) + "\n"
    print(summary)
    with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as output:
        output.write(summary)


if __name__ == "__main__":
    main()
