# Changelog

## Unreleased

- Add T11 compaction, snapshot expiry and orphan removal through Trino/Lakekeeper,
  with exact three-client rows and physical S3 inventory/manifest assertions.
  Preserve default retention negative checks; lower minimums only in the disposable
  maintenance test catalog. Include the maintained table in T5 and every T8 recovery.
- Add T12 Trino schema evolution with exact three-client schemas and old/new rows,
  including nested field addition and integer widening. Query six historical
  snapshots by ID/timestamp after all changes, with fresh PyIceberg snapshot scans
  and mandatory Sail queries; unknown Sail errors and incorrect rows/schema fail.

- Enforce LF line endings: `.gitattributes` normalizes text to LF, a local
  pre-commit hook and CI reject any committed CRLF.
- Add a polished SVG of the Phase A target TLS architecture (services, verified and
  mutual TLS links, nginx-ubi proxies, per-run CA, open gaps), linked from
  ARCHITECTURE.md and TLS-PLAN.md.

- Document how each engine gets S3 access, with a sequence diagram of Sail 0.7.3's
  vended-credentials request and static-key fallback, and the caveat that bucket-wide
  static keys bypass future catalog permissions. Add the prerequisite decision to the
  OpenID/authorization roadmap item.

- Run the full integration gate natively on amd64 and arm64 in parallel, using
  identical source pins, architecture-correct artifact locks and strict image
  provenance. Keep all T1–T10/crash/canary assertions mandatory on both.
- Preserve the required `Integration` check as a fail-closed aggregate, separate
  architecture artifacts, and weekly issue reporting for either architecture.
- Supersede the amd64-only scope by the owner's 2026-11-11 decision; no emulation.

- Add the pinned Sail image, its owner build and strict two-lock provenance check.
- Add isolated Sail service, static AWS secret file and Spark client environment.
- Add T10 exact cross-engine reads and copy-on-write mutations, credential-path
  evidence, plus Sail recreation and secret/hardening assertions.
- Qualify Sail 0.7.3 using static AWS credentials despite its vending header:
  keyless Lakekeeper signing properties, direct S3 signing, no signer requests;
  exact cross-engine reads and mutations pass. Record Actions evidence in
  `docs/SAIL-EVIDENCE.md`.
- Add T8 container-SIGKILL durability tests: kill all eight services after successful
  INSERTs, then kill PostgreSQL, Lakekeeper, SeaweedFS volume and filer during writes.
  Journal acknowledgements and ambiguous outcomes; require exact atomic batches,
  snapshots, fresh independent reads, successful recovery writes and recovery times.
- Keep power loss, fsync/disk-cache qualification and host loss explicitly unproven.
- Investigate remote-signing restart failures: identify a PyIceberg/Fsspec signer
  callback race that sends unsigned S3 requests, also reproducible before restart.
- Add mandatory T9 with full recreation, deterministic concurrent initialization,
  exact unsigned HEAD 403 / GET AccessDenied canary, exact-row recovery controls,
  and a visible notice on upstream success. Preserve the static main path.
- Add an unfiled upstream draft, hypothesis evidence, redacted signer/S3 traces,
  SeaweedFS auth diagnostics, and hash-locked remote-signing client dependencies.

- Add the amd64 Phase 3 cross-repository integration gate: exact SQL/interop,
  storage locations, recreation persistence, negative auth tests, and hardening.
- Require strict revision/artifact-lock image provenance with no exceptions.
  All five current pins pass; missing or mismatched labels remain blocking.
- Adopt the Trino encoding workaround with a mandatory default-encoding canary.
- Separate service secrets, narrow S3 actions, and hash-lock all Python dependencies.
- Add PR/weekly/manual CI, sanitized failure artifacts, a schedule-only failure
  issue, and read-only upstream commit reporting.
