# Changelog

## Unreleased

- Add the pinned Sail image, its owner build and strict two-lock provenance check.
- Add isolated Sail service, static AWS secret file and Spark client environment.
- Add T10 exact cross-engine reads and copy-on-write mutations, credential-path
  evidence, plus Sail recreation and secret/hardening assertions.
- Qualify Sail 0.7.3 using static AWS credentials despite its vending header:
  keyless Lakekeeper signing properties, direct S3 signing, no signer requests;
  exact cross-engine reads and mutations pass. Record Actions evidence in
  `docs/SAIL-EVIDENCE.md`.
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
