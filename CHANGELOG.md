# Changelog

## Unreleased

- Add T13 as a separate authenticated whole-stack profile plus C1–C8 in both
  native Integration jobs, preserving the no-auth regression profile and aggregate
  name. Use real PKCE/JWT and client credentials, stock OPA rows/masks, team Sail
  gateways, live revocation, dependency failures/recovery and durable audit checks.
  Native qualification pending; no production or storage-isolation claim.
- Pin unmerged authz #9 `ed14cf9`, Rauthy #3 `52c3fec` and Trino #8 `9343071`
  with strict source/lock/CPU provenance for both authz outputs. Retain disclosed
  quick-xml/parquet/thrift/SQLite, SvelteKit/fixable RustSec and Iceberg-jar findings;
  no owning security gate is bypassed. Add owner-verified FIDO cache reuse.
- Update the identity diagram to the T13 fixture as built, with runtime status.


- Pin lakekeeper-ubi to fe19d7f (Lakekeeper 0.13.9 with the 0.13.5-0.13.9 security fixes;
  shipped RustSec findings 38 -> 24).
- Pin postgresql-lakekeeper-ubi to 1054729 (PostgreSQL 18.7). PGDG removed the 18.6 RPMs the
  previous pin (0ff367f) locked, so main could no longer build it.
- Add permanent C1–C8 authorization backend acceptance tests, manual-only on both
  native architectures, separate from required Integration. Use the hardened
  rauthy-ubi 1e114b8 owner build with strict provenance, dedicated OpenFGA
  PostgreSQL and backend network, nginx-ubi 9ef9e82, verified TLS, group sync,
  revocation timing, independent client/human credentials, client denials,
  fail-closed recovery and repeat migrations.
- Keep manual evaluations compatible with Phase A's nginx pin: build the proxy
  once and require its evaluation revision to match `images.lock.json`.
- Add the Phase C evaluation topology and link the acceptance contract from the
  authorization platform plan. Retain actual native C1–C8 passes and sanitized
  evidence on both CPUs; observed revocation is 37.76/29.57 ms. Record the no-group
  token compatibility gap, STS-disabled boundary and upstream OpenFGA scan findings
  without claiming production/security qualification.

- Phase A step 7: run the whole integration test over verified TLS on amd64 and
  arm64. Pins: postgresql-lakekeeper-ubi 0ff367f, lakekeeper-ubi baa196b,
  seaweedfs-ubi 80bba40 (PR #81), trino-ubi 685ff5b, sail-ubi e96e068, and the new
  nginx-ubi 9ef9e82 (one pin for both proxies). Server trust uses a per-run CA,
  subject to the documented SeaweedFS residual risk;
  plaintext remains only on loopback inside the catalog and Sail namespaces and on
  the PostgreSQL local socket. T1–T12, T8, T9, T10 and the encoding canary are
  unchanged in meaning. Sail now has its own S3 identity, so T10 records Sail's
  signing identity from the gateway log; REST observations use only the catalog's
  loopback hop inside its own network namespace.
- Add cross-service TLS checks: exact listener inventories, plaintext refusal on
  every exposed listener, loopback isolation, SeaweedFS mTLS-required checks, key
  isolation, a wrong-CA/wrong-hostname/expired matrix for real clients through a
  verified mutation relay and a PostgreSQL impostor, and exact-outcome canaries for
  a known SeaweedFS limitation, reported upstream. Exposure checks repeat after
  T5 and T8.
- Raise the per-architecture job cap from 30 to 45 minutes for the TLS checks.

- Add docs/DECISIONS.md: dated owner decisions, pending decisions and upstream waits.
  Add docs/AUTHZ-PLATFORM-PLAN.md (Phase C plan and future capabilities) and link both
  from the roadmap.
- Refresh diagram status: Sail behind the TLS proxy qualified (sail-ubi e96e068, with the
  documented slow-reader reset and client reattach policy); Trino TLS merged into the Iceberg
  draft branch (685ff5b); Phase C uses OpenFGA as an interim backend while an own
  Cedar-based authorization service is planned.
- Update the Phase A TLS diagram with the approved 2026-11-12 loopback exception,
  merged nginx-ubi proxy and per-component qualification status; cross-service
  integration step 7 remains unrun and the existing SeaweedFS gap note is unchanged.
- Add the Phase B identity target diagram: chosen Rauthy, Keycloak fallback,
  verified TLS, PostgreSQL storage, human and machine token flows, Sail's external
  token file, and Lakekeeper JWT checks. Mark authorization and STS vending as
  future work, and link the diagram from the architecture and Phase B roadmap.
- Add a separate documentation workflow that tests SVG XML and LF endings,
  renders both diagrams, and uploads PNG review artifacts without changing
  the required Integration check, image pins or existing test code.

- Record the owner's 2026-11-13 Phase B choice: Rauthy, with Keycloak as the tested
  fallback. Plan a hardened `rauthy-ubi` image and Sail's externally supplied
  token-file path, based on the native amd64/arm64 IdP bake-off evidence.
- Make the separate IdP bake-off `workflow_dispatch` only, so its documented
  compatibility failures do not appear on future PRs. Keep required `Integration`
  unchanged.

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
