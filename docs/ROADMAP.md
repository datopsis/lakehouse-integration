# Roadmap

Sail 0.7.3 is qualified as the second query engine alongside Trino, with PyIceberg
as an independent client: [T10, restart and credential evidence](SAIL-EVIDENCE.md).
All five current image pins passed strict provenance; future pin changes still
require review and exact labels, with no allowances.

- TLS between all services: REST, S3, PostgreSQL, Seaweed control HTTP/gRPC, and Trino;
  include certificate verification, lifecycle and negative tests.
- OpenID login for Lakekeeper **with authorization**, plus authenticated Trino access.
- Review a sail-ubi bump to the first release containing configurable delegation
  (`0c8333a349e5438e4b37fe984b9e3a45befc7bff`) and explicitly omit vending.
  Current 0.7.3 works with static credentials despite requesting vending. Do not
  assume an unreleased version number or change the static main path.
- ARM64 images and execution, after amd64 qualification; no emulated green claims.
- Remote-signing restart investigation resolved as a PyIceberg/Fsspec concurrent
  signer-registration bug: T9 deterministically exposes the unsigned-request gap
  after full recreation and verifies exact-row recovery. Review an upstream fix
  when the canary announces signed success; retain the canary until then. See the
  [unfiled draft report](known-issues/remote-signing.md). Remote signing stays OFF
  the static-credential main path; fresh-client success is not a concurrency fix.
- Crash durability: kill/power-loss, restart ordering, host loss, backup/restore,
  replication, and encryption-key recovery; current tests cover graceful down/up only.
- Trino upstream-fix follow-up: keep draft PR #2's vulnerability gate blocking
  release until upstream jar fixes are available and the owning repo qualifies them.
  Replace the deliberate pre-release test pin only after review; make no security claim.
- Drop parquet.writer.delta-length-byte-array-encoding-enabled=false after the
  default-encoding canary passes, its exact mutation rows are independently verified,
  and the upstream fix is reviewed. Canary success must remain visible in CI.
- Qualify the documented Podman API runtime path in CI, including hardening and
  bridge routing; Docker is the current runtime evidence path.
