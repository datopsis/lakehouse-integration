# Roadmap

- Merge the owning Lakekeeper/SeaweedFS provenance fixes, review coordinator-supplied
  pins as one-line lock changes, and require strict labels to pass. Never add allowances.
- TLS between all services: REST, S3, PostgreSQL, Seaweed control HTTP/gRPC, and Trino;
  include certificate verification, lifecycle and negative tests.
- OpenID login for Lakekeeper **with authorization**, plus authenticated Trino access.
- Qualify Sail 0.7.3 as the second query engine with T10 (PR CI evidence pending).
  Track upstream configurable delegation commit `0c8333a349e5438e4b37fe984b9e3a45befc7bff`;
  review a sail-ubi bump to the first release containing it and explicitly omit
  vending. Do not assume an unreleased version number or change the static main path.
- ARM64 images and execution, after amd64 qualification; no emulated green claims.
- Investigate remote-signing restart behaviour: the spike's long-lived PyIceberg
  remote-signing reader hit HeadObject 403 after recreation. Fresh-client success
  does not explain that failure. Keep it out of the static-credential main path.
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
