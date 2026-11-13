# Roadmap

Sail 0.7.3 is qualified as the second query engine alongside Trino, with PyIceberg
as an independent client: [T10, restart and credential evidence](SAIL-EVIDENCE.md).
All five current image pins passed strict provenance; future pin changes still
require review and exact labels, with no allowances.

- [x] T11 table maintenance: compaction, snapshot expiry with physical S3 deletion,
  orphan removal with manifest protection, exact three-client reads, default
  retention refusals, and persistence after T5/T8 on both native architectures.
- [ ] Interrupt maintenance mid-operation; current T8 preserves completed maintenance.
- [x] T12 schema evolution and historical snapshots: exact schemas, field identity,
  old/new rows and time travel across add/rename/drop/widen/nested-add; mandatory
  three-client assertions and exact-outcome Sail canaries where needed.
- TLS between all services: REST, S3, PostgreSQL, Seaweed control HTTP/gRPC, and Trino;
  include certificate verification, lifecycle and negative tests.
- [ ] Phase B: build a hardened `rauthy-ubi` image and qualify OpenID login on both
  native architectures. Owner chose Rauthy on 2026-11-13, with Keycloak as the
  tested fallback; see the [IdP bake-off decision and evidence](IDP-BAKEOFF.md).
  Sail 0.7.3 needs an externally supplied token-file path with token lifecycle
  management; it has no native client-credentials grant provider.
  The [Phase B identity diagram](diagrams/lakehouse-identity-architecture.svg) shows
  human PKCE login, machine tokens, Sail's external token file, and Lakekeeper JWT
  validation over verified TLS, with PostgreSQL as Rauthy's target storage.
  Groups are carried for future authorization; Phase C (OpenFGA or Cedar,
  undecided) and Phase D (SeaweedFS STS credential vending) are marked not built.
- OpenID login for Lakekeeper **with authorization**, plus authenticated Trino access.
  Prerequisite decision: while engines hold bucket-wide static S3 keys, catalog
  permissions do not protect data (see "How each engine gets S3 access" in
  [ARCHITECTURE.md](ARCHITECTURE.md)). Decided 2026-11-11: the catalog grants
  per-table S3 access by credential vending through SeaweedFS STS (being qualified
  in seaweedfs-ubi). Remote signing does not isolate tables on SeaweedFS (per
  Lakekeeper's docs), so it stays off for table isolation. Then remove the engines'
  static keys.
- Review a sail-ubi bump to the first release containing configurable delegation
  (`0c8333a349e5438e4b37fe984b9e3a45befc7bff`) and explicitly omit vending.
  Current 0.7.3 works with static credentials despite requesting vending. Do not
  assume an unreleased version number or change the static main path.
- [x] ARM64 images and execution for this integration test, alongside qualified
  amd64: native parallel runners, identical mandatory assertions and strict
  per-architecture provenance. Owner authorized 2026-11-11; no emulated green claims.
- Remote-signing restart investigation resolved as a PyIceberg/Fsspec concurrent
  signer-registration bug: T9 deterministically exposes the unsigned-request gap
  after full recreation and verifies exact-row recovery. Review an upstream fix
  when the canary announces signed success; retain the canary until then. See the
  [unfiled draft report](known-issues/remote-signing.md). Remote signing stays OFF
  the static-credential main path; fresh-client success is not a concurrency fix.
- [x] Crash durability — container-kill scope: T8 kills all services after acknowledged
  writes and individually kills PostgreSQL, Lakekeeper, the volume server, and filer
  during INSERTs. Exact acknowledged rows, atomic in-flight outcomes, snapshots,
  independent fresh reads, new writes, and per-component recovery time are required.
- [ ] Power-loss durability: container SIGKILL leaves the host page cache alive;
  qualify fsync and disk-cache behavior with real power-loss testing.
- [ ] Host-loss durability, restart-order permutations, backup/restore, replication,
  and encryption-key recovery. T8 is single-host evidence only.
- Trino upstream-fix follow-up: keep draft PR #2's vulnerability gate blocking
  release until upstream jar fixes are available and the owning repo qualifies them.
  Replace the deliberate pre-release test pin only after review; make no security claim.
- Drop parquet.writer.delta-length-byte-array-encoding-enabled=false after the
  default-encoding canary passes, its exact mutation rows are independently verified,
  and the upstream fix is reviewed. Canary success must remain visible in CI.
- Qualify the documented Podman API runtime path in CI, including hardening and
  bridge routing; Docker is the current runtime evidence path.
