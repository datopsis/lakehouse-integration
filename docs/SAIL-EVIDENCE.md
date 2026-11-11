# Sail 0.7.3 interoperability evidence

Qualified on amd64 in [Actions run 42968939164](https://github.com/datopsis/lakehouse-integration/actions/runs/42968939164)
at integration commit `647bcbf`. Actual logs and the sanitized artifact
`lakehouse-42968939164-1` were downloaded and inspected, including `builds.json`,
`results.json`, `probe.log`, `sail-traffic.log`, and `sail-capture.log`.
Artifacts expire after 14 days. The PR carries the latest head's CI result.

| Job | Result | Duration |
| --- | --- | --- |
| Integration | Passed, including all builds/provenance, T1–T7, T10, encoding canary and cleanup | 5m 36s |
| Upstream commits | Passed | 7s |
| Weekly failure issue | Not run: schedule-only job, this is a PR | — |

## Credential result

**Sail uses its static AWS credentials successfully despite requesting vending.**
Lakekeeper remains `sts-enabled=false`. Its HTTP 200 table response contains
`s3.signer=S3V4RestSigner` and `s3.remote-signing-enabled=true`. The
`storage-credentials` list contains one prefix/config entry with endpoint/region
properties, but no access key, secret key, or session token. Both the top-level
config and nested entry are checked for absence of those keys.

The passive capture filters to Sail's container IP; runner, Trino and PyIceberg
requests cannot satisfy it. The inspected trace shows:

- `x-iceberg-access-delegation: vended-credentials` on Sail requests.
- Remote-signing properties in the actual responses to Sail.
- S3 `authorization: AWS4-HMAC-SHA256 Credential=[REDACTED]/20261111/local/s3/aws4_request`.
  Before redaction, the gate requires the credential to equal the fixture's
  static access key supplied in Sail's own environment file.
- Zero POST requests to signer paths. Capture: 844 packets captured/received,
  zero dropped. Packet counts include bridge duplication, not unique requests.

Thus the observed behavior is static credential use, with no remote-signing
attempt observed. No failure canary is appropriate: T10 is a mandatory success
test. No Sail patch, version swap, storage-profile change, or provenance exemption
was needed. The image's startup-only `docs/ICEBERG.md` blocker prediction does not
establish failure in this fixture; this run exercises actual storage operations.

## Exact row assertions

Each Sail mutation is followed by exact Sail and Trino SELECTs and a **new
PyIceberg process/catalog/FileIO**. All scans sort by `id` and compare full rows.

| Stage | Required rows `(id, label)` |
| --- | --- |
| Sail CREATE + INSERT | `(100, sail-alpha), (200, sail-beta), (300, sail-gamma)` |
| Sail UPDATE id=200 | `(100, sail-alpha), (200, sail-updated), (300, sail-gamma)` |
| Sail DELETE id=300 | `(100, sail-alpha), (200, sail-updated)` |
| Sail reads Trino mutations | `(1, alpha), (2, updated)` |
| Sail reads PyIceberg writes | `(10, py-alpha), (20, py-beta)` |
| New Sail write after recreation | `(100, sail-alpha), (200, sail-updated), (400, sail-after-restart)` |

The Sail table is unpartitioned Iceberg v2/Parquet with explicit copy-on-write
UPDATE/DELETE. The three stages have distinct snapshot IDs and zero delete files.
T4 verifies all four tables' metadata/data/delete objects and exact PostgreSQL
catalog names. Sail's table location is `s3://warehouse/from_sail`, registered in
the same Lakekeeper warehouse; Trino/PyIceberg tables use catalog-assigned paths.

T5 replaces all eight container IDs, retains volumes/secrets, and rereads every
table with fresh clients. Sail also reads the new Trino row `(30, after-restart)`
in the PyIceberg-created table and the default-encoding canary. The new Sail row
is read exactly by Trino and another fresh PyIceberg process. T7 checks Sail's
UID 10001, read-only root, zero capabilities, no-new-privileges, internal network,
no published ports and absence of other services' secrets/mounts.

Sail reads Trino's positional-delete scan with the adopted delta-length encoding
setting **false**. PyIceberg's default-encoding canary still yields exactly
`Not yet implemented: DecodeArrow of DictAccumulator for DeltaLengthByteArrayDecoder.`
before and after recreation. Its success-notice and unexpected-error gates remain.

## Provenance and limits

All five images passed strict provenance. Sail's revision label equals
`6e6f65a69108f4c6870eab26f356dccb41efbf35`. Its artifact-lock label equals
`bbb66d68cbb0a9533895612576bbbbd7b6b79c8df8c733eb0aa2c749c2ebd8ca`, the SHA-256
of `artifacts/sail.lock.json` followed by `artifacts/rpms.lock.json`, exactly the
owning build script's contract. Individual input hashes are retained in
`builds.json`; changing either lock fails admission. Sail's client/tool environment
uses that source pin's hash-locked requirements separately from the main Arrow
canary environment. Local Ruff, Zizmor and all nine unit tests pass.

This qualifies the small private static-credential fixture, not TLS/authentication,
ARM64, production security, load, crash durability, shared-file credential
resolution, MERGE, partitioned mutations, merge-on-read writes or remote signing.
In particular, 0.7.3 merge-on-read UPDATE is unsupported; no such claim is made.
No container execution was attempted in the development sandbox; runtime evidence
comes from Actions. Lakekeeper and Sail authentication gaps remain documented.

Upstream [0c8333a349e5438e4b37fe984b9e3a45befc7bff](https://github.com/lakehq/sail/commit/0c8333a349e5438e4b37fe984b9e3a45befc7bff)
adds configurable delegation after 0.7.3. Follow up with a separately reviewed
sail-ubi pin to the first release containing it, explicitly omit delegation, and
rerun T10. No unreleased version number is assumed.
