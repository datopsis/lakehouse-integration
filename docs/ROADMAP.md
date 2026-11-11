# Roadmap

- Merge the owning Lakekeeper/SeaweedFS provenance fixes, review coordinator-supplied
  pins as one-line lock changes, and require strict labels to pass. Never add allowances.
- TLS between all services: REST, S3, PostgreSQL, Seaweed control HTTP/gRPC, and Trino;
  include certificate verification, lifecycle and negative tests.
- OpenID login for Lakekeeper **with authorization**, plus authenticated Trino access.
- Sail as a second query engine (PyIceberg remains an independent client).
- ARM64 images and execution, after amd64 qualification; no emulated green claims.
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
