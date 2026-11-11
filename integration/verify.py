"""Mandatory, strict image provenance gate. There are no repo exceptions."""

import json

from build import PINS, REPORTS


def main():
    results = json.loads((REPORTS / "builds.json").read_text())
    assert results.keys() == PINS.keys(), "Missing or unexpected image build evidence"
    errors = []
    for repo, revision in PINS.items():
        result = results[repo]
        print(repo + ": " + result["status"])
        for error in result.get("provenance_errors", []):
            print("  " + error)
        if result["status"] != "pass" or result.get("revision") != revision:
            errors.append(repo)
    assert not errors, "Strict provenance FAILED: " + ", ".join(errors)


if __name__ == "__main__":
    main()
