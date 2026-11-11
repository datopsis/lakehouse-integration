# Changelog

## Unreleased

- Add T8 container-SIGKILL durability tests: kill all seven services after successful
  INSERTs, then kill PostgreSQL, Lakekeeper, SeaweedFS volume and filer during writes.
  Journal acknowledgements and ambiguous outcomes; require exact atomic batches,
  snapshots, fresh independent reads, successful recovery writes and recovery times.
- Keep power loss, fsync/disk-cache qualification and host loss explicitly unproven.

- Add the amd64 Phase 3 cross-repository integration gate: exact SQL/interop,
  storage locations, recreation persistence, negative auth tests, and hardening.
- Require strict revision/artifact-lock image provenance with no exceptions.
  Initial Lakekeeper/SeaweedFS pins intentionally remain failing until reviewed fixes.
- Adopt the Trino encoding workaround with a mandatory default-encoding canary.
- Separate service secrets, narrow S3 actions, and hash-lock all Python dependencies.
- Add PR/weekly/manual CI, sanitized failure artifacts, a schedule-only failure
  issue, and read-only upstream commit reporting.
