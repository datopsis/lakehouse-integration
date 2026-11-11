"""Mandatory, strict image provenance gate. There are no repo exceptions."""

import json

from build import PINS, REPORTS, native_architecture


def main():
    if not __debug__:
        raise RuntimeError("Assertions must be enabled; remove -O/PYTHONOPTIMIZE")
    results = json.loads((REPORTS / "builds.json").read_text())
    assert results.keys() == PINS.keys(), "Missing or unexpected image build evidence"
    architecture = native_architecture()
    errors = []
    for repo, revision in PINS.items():
        result = results[repo]
        print(repo + ": " + result["status"] + "; architecture=" + str(result.get("architecture")))
        for error in result.get("provenance_errors", []):
            print("  " + error)
        if (
            result["status"] != "pass"
            or result.get("revision") != revision
            or result.get("architecture") != architecture
            or result.get("expected_architecture") != architecture
        ):
            errors.append(repo)
    assert not errors, "Strict provenance FAILED: " + ", ".join(errors)


if __name__ == "__main__":
    main()
