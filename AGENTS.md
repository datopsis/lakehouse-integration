# Agent guidance

Read README.md, SECURITY.md, docs/ARCHITECTURE.md, and docs/ROADMAP.md before changes.
The feasibility evidence lives on spike/feasibility; never modify/delete that branch.

Binding owner decisions:
- Native amd64 and arm64. The owner superseded the amd64-only decision on
  2026-11-11. Both must run the complete identical gate; no QEMU or emulation.
- Keep S3 credentials and PostgreSQL passwords enabled.
- Lakekeeper login stays off only on the private test network; document the gap.
- Trino's documented isolated-test insecure mode has no published listener.
- Keep the main Trino delta-length encoding setting false AND run the default-encoding
  canary after UPDATE/DELETE. Accept only the exact known OSError. Successful exact
  reads must announce upstream fixed it; any other error fails. Never silently skip.
- Static S3 credentials, Trino vending off, PyIceberg explicitly client-managed.
- Strict provenance is mandatory for every image: source revision equals the pin;
  artifact-lock label equals the SHA-256 of its repository lock. Missing/mismatched
  labels fail, including the initial Lakekeeper and SeaweedFS pins. No exceptions.
- Pins live only in images.lock.json. Updates are reviewed one-line changes; do not
  auto-follow main, add fallback tags, alter owning repos, or rewrite image labels.
- The draft Trino PR pin is a deliberate pre-release exception for testing only.
  Do not imply security qualification, bypass its vulnerability gate, or alter jars.

Never weaken a check to get green. Keep exact rows/operations, per-service secrets,
negative tests, full recreation, pipefail, hashed Python installs, failure artifacts,
and redaction before upload. Run local lint/unit tests and wait for PR CI. Runtime
restrictions must be reported as unverified, never as passing evidence. Use a fresh
workspace to run the fixture; no production database may be targeted.

No GitHub settings/secrets/permissions changes, other-repo modifications, sign-offs,
AI or Co-Authored-By trailers, force-pushes, or merges. CI write permission belongs
only to the schedule-failure issue job. Dependency and image changes require review.
