# Lakehouse feasibility spike

This is a feasibility experiment, not the Phase 3 integration test or production qualification.
All code and evidence remain on `spike/feasibility`. No PR was opened, no other repository
was modified, and no image was published.

**Verdict: feasible with explicit configuration.** The final run passed Trino SQL,
bidirectional PyIceberg interoperability (including Trino UPDATE/DELETE), full-stack
recreation and a post-recreation write/read. Use static S3 credentials with Trino vending
off, and disable Trino's delta-length byte-array encoding for the pinned PyArrow reader.
The image-provenance gaps, vulnerability gate, login gaps and long-lived remote-signing
recovery failure below remain unresolved. A green feasibility run is not a release gate.

## Evidence and pinned inputs

Final experiment: [run 42954359788](https://github.com/datopsis/lakehouse-integration/actions/runs/42954359788),
code commit `fc08ce9fc112c1180fcbbd908665aeaaaec0b142`.
The later documentation/evidence commit changes no executed code. Final
[results](spike/evidence/42954359788/results.json),
[probe log](spike/evidence/42954359788/probe.log),
[image evidence](spike/evidence/42954359788/builds.json) and
[GitHub timings](spike/evidence/42954359788/run.json) are retained on this branch.
Baseline with default Parquet encoding: [run 42953102735](https://github.com/datopsis/lakehouse-integration/actions/runs/42953102735),
code commit `17214f4`. Its negative results are retained in
[`spike/evidence/42953102735/`](spike/evidence/42953102735/).

| Image repository | Exact source commit | Repository-owned build command |
| --- | --- | --- |
| datopsis/postgresql-lakekeeper-ubi | `93666c251ca2c4e6618ddd35a669c4c3ea380313` | `bash scripts/build-offline.sh` (Docker) |
| datopsis/lakekeeper-ubi | `dac1d6b06ef30690a8784bf7e8490bec1f58a1cf` | `bash scripts/build.sh --arch amd64 --runtime podman --tag localhost/lakekeeper-ubi:spike` |
| datopsis/seaweedfs-ubi | `1bfd88f26ff63f9b33839ab1d5477e8f7f57376c` | `bash scripts/build.sh amd64` (Podman) |
| datopsis/trino-ubi | `964802b7afd3ae526039ef7dc7fcf605ce3d5b26` | `bash scripts/build.sh amd64` (Docker) |

`spike/build.py` follows Lakekeeper's `scripts/build-postgres.sh`: fetch the exact SHA,
check detached HEAD and clean tracked source, build with the repository's script, inspect
the loaded image architecture/revision/lock labels. Trino has the requested
`refs/pull/2/head` fetch fallback, still followed by the exact HEAD assertion. Podman images
are exported and loaded into Docker for Compose. No product image is fetched by a mutable
tag. The SeaweedFS script's digest-pinned Cosign binary is extracted without starting its
container and executed on the runner; the signature admission checks remain intact.

There are **real provenance blockers for a strict Phase 3 label gate**:

- PostgreSQL and Trino emit matching source revision and artifact-lock SHA-256 labels.
- Lakekeeper does not set its own revision label. Its loaded image inherits
  `9d7bd388a99de116058bd54b77737e2863cb3d45` from its locked UBI base, which does **not**
  equal the pinned Lakekeeper source commit. It also has no artifact-lock hash label.
- SeaweedFS emits the correct source revision and upstream commit, but has no artifact-lock
  hash label.

The harness records these exact failures as `built-with-provenance-gaps`, verifies the
inherited label against the locked base, and compares Lakekeeper/SeaweedFS binaries copied
from the finished images with the reviewed locks. Binary hashes are additional evidence,
not a substitute for image provenance. No labels, build scripts, locks or upstream files
were changed to hide these gaps.

The pinned Trino draft PR remains vulnerability-blocked. Its [amd64 gate](https://github.com/datopsis/trino-ubi/actions/runs/42823620083/job/129855104023)
reported `High/Critical: 9 scanner findings; 9 with fixes; 0 without fixes` (Trivy/Grype,
not nine necessarily distinct vulnerabilities). The spike uses the unchanged jars and
build script, does not rerun the scanners, and makes no suppression, exemption or clean
security claim. PR #2 remains untouched.

## 1. SeaweedFS: separated roles work with Lakekeeper

**Measured in the baseline and final run:** warehouse registration succeeded with valid credentials;
registration using the correct access key and a wrong secret returned HTTP 400 with
`The request signature we calculated does not match the signature you provided`.
Trino's writes and subsequent reads exercised the object path through all four roles.

The exact topology is [`spike/compose.yaml`](spike/compose.yaml), derived from the pinned
SeaweedFS README, `docs/CONFIGURATION.md`, `SECURITY.md` and `compose.yaml`:

| Role | Flags | Durable state |
| --- | --- | --- |
| master | `-mdir=/data -ip=master -volumeSizeLimitMB=64` | named volume at `/data` |
| volume | `-dir=/data -ip=volume -mserver=master:9333 -max=4` | named volume at `/data` |
| filer | `-ip=filer -master=master:9333 -defaultStoreDir=/data` | named volume at `/data` (embedded store) |
| s3 | `-filer=filer:8888 -ip.bind=0.0.0.0 -config=/run/secrets/s3.json` | none; wholly read-only |

The 64 MiB volume-size limit bounds this tiny runner fixture; it is not production sizing.
The S3 JSON contains one explicitly named identity with generated access/secret keys and
`Admin`, `Read`, `Write`, `List`, `Tagging` actions. This is a broad fixture identity, not
least-privilege qualification. It is mounted read-only, root-owned/group 0, mode 0440.
Mounted configuration also avoids the documented environment-bootstrap key-ID logging path.

Create the bucket before registering the warehouse. The image disables auto-create:
`weed shell -master=master:9333 -filer=filer:8888`, then
`s3.bucket.create -name warehouse`. Lakekeeper's working storage profile is:

```json
{
  "type": "s3",
  "bucket": "warehouse",
  "region": "local",
  "endpoint": "http://s3:8333",
  "path-style-access": true,
  "flavor": "s3-compat",
  "sts-enabled": false
}
```

Register it using a separate `storage-credential` with `type: s3`,
`credential-type: access-key`, and the generated keys. Lakekeeper's default
`remote-signing-enabled: true` is left intact for the delegation experiments.

Every service uses non-root image UID (SeaweedFS 1000, PostgreSQL 26, Lakekeeper 999,
Trino 10001), group 0, read-only root, dropped capabilities and no-new-privileges.
The probe asserts UID/CapEff/NoNewPrivs from PID 1 and Docker's mount/network settings.
All services share a Docker `internal: true` network, with **no published ports**. The Linux
runner accesses bridge IPs as a trusted test client; temporary hostnames resolve catalog,
S3 and Trino. Do not expose master/volume/filer: they bypass S3 authorization.
No gRPC mTLS, volume JWT or S3 TLS qualification is claimed.

PostgreSQL has a generated admin password file and a generated least-privileged Lakekeeper
role password, provisioned by the pinned Lakekeeper fixture's SQL. Lakekeeper receives its
PostgreSQL URL and encryption key through generated environment files. No credentials
exist in committed configuration; generated files and full runtime configuration are not
uploaded. Diagnostics are scrubbed before artifact upload.

## 2. Trino to Lakekeeper

**Baseline and final run passed:** CREATE SCHEMA, CREATE TABLE (Iceberg v2/Parquet), INSERT, SELECT,
UPDATE, DELETE, `$snapshots` and `$history`. Starting rows were `(1, alpha), (2, beta),
(3, gamma)`; after UPDATE and DELETE the asserted rows were `(1, alpha), (2, updated)`.
The history contained four snapshots, including overwrite and delete operations.

[`spike/trino/catalog/iceberg.properties`](spike/trino/catalog/iceberg.properties) contains
the exact final catalog configuration. The working connection settings are:

```properties
connector.name=iceberg
iceberg.catalog.type=rest
iceberg.rest-catalog.uri=http://catalog:8181/catalog
iceberg.rest-catalog.warehouse=qualification
iceberg.rest-catalog.security=NONE
iceberg.rest-catalog.vended-credentials-enabled=false
iceberg.rest-catalog.server-assigned-table-location-enabled=true
fs.s3.enabled=true
s3.endpoint=http://s3:8333
s3.region=local
s3.path-style-access=true
s3.aws-access-key=${ENV:S3_ACCESS_KEY_ID}
s3.aws-secret-key=${ENV:S3_SECRET_ACCESS_KEY}
```

The REST URI includes `/catalog`; `qualification` is the registered warehouse name.
Server-assigned locations let Lakekeeper choose the table paths. No OAuth properties
or token are configured. Trino's S3 keys are injected from a generated env file and
resolved by Trino, not committed as literals.

**Vending interferes; static client credentials work.** With STS disabled, Lakekeeper
returns remote-signing properties and no vended access key, including when the client
requests `vended-credentials`. Turning Trino's vending property on caused:

```text
GENERIC_INTERNAL_ERROR: Error processing metadata for table spike.from_trino
java.lang.NullPointerException: accessKey is null
io.trino.plugin.iceberg.catalog.rest.S3VendedCredentials.<init>
```

The same table is readable with vending off. Lakekeeper's remote-signing hints did not
interfere with Trino's native S3/static-credential mode. This does not demonstrate Trino
remote-signing support; it demonstrates the working direct-S3 mode and failed vending mode.
The behavior is consistent with the pinned
[Lakekeeper delegation implementation](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/service/storage/s3.rs).

Lakekeeper login is **off**, as requested. Trino also uses its documented explicit
`TRINO_UBI_ALLOW_INSECURE=true` isolated-test mode, without a published listener. Trino
TLS/password login is an additional unqualified gap, not a production recommendation.
The Trino runtime requires writable `/var/lib/trino` and executable `/tmp/trino` tmpfs;
the latter is required for native libraries. Both retain nosuid/nodev; data tmpfs is noexec.

## 3. Cross-engine interoperability and the encoding blocker

PyIceberg `0.12.0` and PyArrow `25.0.1` match the pinned Lakekeeper storage fixture.
The baseline proved **Trino reads PyIceberg-written rows**, but the reverse direction
failed after Trino UPDATE/DELETE:

```text
pyiceberg/io/pyarrow.py, _read_deletes
  ds.Scanner.from_fragment(fragment=delete_fragment).to_table()
OSError: Not yet implemented: DecodeArrow of DictAccumulator for DeltaLengthByteArrayDecoder.
```

This is a delete-file decoding failure after catalog/S3 access, not an authentication
failure. PyIceberg requests a dictionary for the delete-file `file_path` column; Arrow's
DELTA_LENGTH_BYTE_ARRAY dictionary decoder is unimplemented. See the pinned
[PyIceberg reader](https://github.com/apache/iceberg-python/blob/pyiceberg-0.12.0/pyiceberg/io/pyarrow.py)
and [Arrow decoder](https://github.com/apache/arrow/blob/apache-arrow-25.0.1/cpp/src/parquet/decoder.cc).

The final experiment adds this supported **catalog configuration**, without replacing any
jar or changing any image:

```properties
parquet.writer.delta-length-byte-array-encoding-enabled=false
```

[Trino 484's writer configuration](https://github.com/trinodb/trino/blob/484/plugin/trino-hive/src/main/java/io/trino/plugin/hive/parquet/ParquetWriterConfig.java)
provides the switch; it selects PLAIN instead of DELTA_LENGTH_BYTE_ARRAY as the
non-dictionary fallback. **Measured in [run 42953755477](https://github.com/datopsis/lakehouse-integration/actions/runs/42953755477): both directions passed**, including
PyIceberg reading before and after Trino UPDATE/DELETE. The same run verified:

| PyIceberg mode | Observed FileIO | Read result |
| --- | --- | --- |
| Default delegation, client S3 keys supplied | `FsspecFileIO` with `S3V4RestSigner` | pass |
| `header.X-Iceberg-Access-Delegation=client-managed`, static keys | `PyArrowFileIO`, no signer | pass |
| `header.X-Iceberg-Access-Delegation=remote-signing`, no client S3 keys | `FsspecFileIO` with `S3V4RestSigner` | pass |

The final main path chooses explicit `client-managed` for PyIceberg so both engines use
static S3 credentials. Lakekeeper may select a remote-signing FileIO when the header is
omitted, even if client credentials were supplied. Record the actual mode rather than
inferring it from credentials present in the client configuration.

Do not describe the baseline as full bidirectional interoperability. Do not silently skip
mutation/delete-file reads to obtain a green test. The default-encoding failure is retained
for the coordinator even if the configuration workaround succeeds.

## 4. Stop/restart persistence

The test uses `docker compose down` (without `--volumes`), then `up -d`, and verifies
that all seven service container IDs changed. The PostgreSQL, master, volume and filer
named volumes, S3 identity and Lakekeeper encryption key are retained. **Baseline:** Trino
reread the correct contents of both tables after this replacement. Its PyIceberg reread
hit the same encoding failure, so the post-restart write was not reached.

The encoding experiment [42953755477](https://github.com/datopsis/lakehouse-integration/actions/runs/42953755477)
again proved both tables readable by Trino after replacement, but its still-running
PyIceberg remote-signing reader failed at `HeadObject` with HTTP 403 / `Forbidden`.
The exact cause of that live-client recovery failure is not established; do not claim
transparent remote-signing recovery from this experiment.

**Final experiment passed.** A fresh independent PyIceberg process after recreation,
matching the existing Lakekeeper storage fixture's fresh-engine approach, read both tables
in static mode; Trino did too. A subsequent Trino insert of `(30, after-restart)` was read
with exact row contents by PyIceberg. A separate fresh-client remote-signing read without
S3 keys also passed. All seven container IDs changed, and kernel/runtime hardening was
rechecked. The recreation/reverification segment took 57.44 seconds. Fresh-client success
does not explain or erase the earlier live-client 403.
This is graceful one-host stop/recreate persistence, not power-loss, crash recovery,
replication, backup/restore, host-loss or key-rotation qualification.

## 5. Cost on GitHub-hosted amd64

All runs use `ubuntu-24.04` and assert `uname -m = x86_64`. Builds are sequential on one
runner, from fresh source fetches with no cross-run image cache. Build timings include
acquisition, verification and Podman-to-Docker transfer; bases are reused within a job.

Final run (2026-11-11, 03:41:05–03:45:43 UTC):

| Segment | Seconds |
| --- | ---: |
| PostgreSQL acquisition/build/image verification | 37.38 |
| Lakekeeper acquisition/build/image verification | 23.63 |
| SeaweedFS acquisition/build/image verification | 27.92 |
| Trino acquisition/build/image verification | 34.79 |
| **All four image builds, including acquisition/verification/transfer** | **123.72** |
| **Service startup, probes, full recreation and rereads/new write** | **90.83** |
| **Builds + service experiment** | **214.55 (3m34.55s)** |
| Runner prerequisite step | 32 |
| Final diagnostics and teardown step | 27 |
| **Whole GitHub job, including checkout/upload/overhead** | **278 (4m38s)** |

The four jobs together consumed **968 seconds (16m08s)** of observed runner wall time.
That includes unsuccessful exploration, not just the successful final configuration.

Earlier experiment costs: initial harness debugging run 2m56s; encoding/mode experiment
4m02s; baseline integration run 4m32s (151.28s acquisition/build/verification, 76.97s service experiment). The initial run
[42952708701](https://github.com/datopsis/lakehouse-integration/actions/runs/42952708701)
was falsely green because default shell pipelines hid failures behind `tee`; its artifacts
show the Lakekeeper label mismatch and a misquoted tmpfs mount. It is **not passing evidence**.
The final workflow explicitly selects `shell: bash` (pipefail), fixes the mount and records
provenance gaps without misrepresenting them as valid labels.

These are elapsed runner times, not an invoice or performance benchmark. They exclude queue
wait and do not include a fresh vulnerability scan. Actions artifacts retain redacted full
logs for 14 days; selected JSON, probe logs and run metadata are committed under
`spike/evidence/` so the findings do not depend on artifact retention.

## What Phase 3 should copy or avoid

Copy the pinned fetch/HEAD checks, repository-owned build entry points, loaded-image
checks, separated-role Compose flags, explicit persistent paths, precreated bucket,
static identity file, environment-resolved Trino credentials, vending-off setting,
server-assigned locations, explicit PyIceberg `client-managed` delegation, exact row/history
assertions and full-stack recreation with a fresh reader.
Keep generated credentials and retained encryption key consistent across restart.
Keep pipefail, failure artifacts and secret redaction.

Resolve the Lakekeeper revision/lock and SeaweedFS lock-label gaps in their owning repos
before claiming strict source-to-image label verification. Keep the Trino vulnerability
gate blocking release; spike feasibility does not justify an exemption. Preserve the
encoding failure as a regression case and explicitly decide whether Phase 3 adopts the
measured writer setting (`parquet.writer.delta-length-byte-array-encoding-enabled=false`)
or waits for upstream decoder compatibility. Pin/hash the complete Python
dependency set for the final test; this spike records `pip freeze` but only pins its two
principal Python packages. Avoid vending against this non-STS profile and avoid treating
remote-signing response metadata as proof that Trino implements remote signing.

Do not copy the insecure login/TLS profiles, broad fixture S3 identity or one-volume
storage topology into production. Split the spike's shared secret directory into
per-service mounts so the S3 service cannot read PostgreSQL password files. This experiment does not qualify ARM64, auth/TLS,
least privilege, concurrency/load, alternate Iceberg formats, large tables, replication,
crash durability, upgrades or production readiness. The final Phase 3 test remains future
work; this branch intentionally retains the throwaway implementation and negative evidence.

## Minimal files and rerun

- [Workflow](.github/workflows/feasibility.yml): push to `spike/**` plus
  `workflow_dispatch`, `ubuntu-24.04`, `contents: read`, full action SHAs, 60-minute cap.
  Documentation/evidence-only pushes are ignored to avoid rebuilding unchanged code.
- [Source pins](spike/pins.json) and [build harness](spike/build.py).
- [Compose](spike/compose.yaml), [Trino config directory](spike/trino/), and
  [PostgreSQL initialization SQL](spike/postgres-init.sql).
- [Probe/bootstrap/secret generation](spike/probe.py) and
  [redaction/teardown](spike/cleanup.py).

Rerun the workflow with `workflow_dispatch` targeting `spike/feasibility`, or push a code
change on a `spike/**` branch. The scripts expect a fresh runner workspace. No GitHub
secrets or settings changes are required. All runtime containers and volumes were removed
in the successful final cleanup step. Do not use this throwaway harness as the final test
without resolving the documented Phase 3 choices and gaps.
