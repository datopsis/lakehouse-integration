# Lakehouse integration

One native amd64 and arm64 integration gate for the six Datopsis image repositories: Trino queries
Iceberg v2 / Parquet through Lakekeeper's REST catalog, PostgreSQL stores catalog
metadata, and separated SeaweedFS master/volume/filer/S3 roles store table objects.
Sail is the second query engine; PyIceberg is an independent client. nginx-ubi
terminates TLS for Lakekeeper and Sail. Nothing is published to a host port.

**Phase A configures TLS for every network hop.** A fresh test CA is created for
each run; server verification is subject to the SeaweedFS residual risk below.
Qualification status is recorded in
[Step 7 evidence](docs/TLS-PLAN.md#step-7-evidence). The only plaintext is on 127.0.0.1 inside one network namespace (each proxy to its
Lakekeeper or Sail backend) and the PostgreSQL container-local Unix socket used for
administrator provisioning, as the owner decided on 2026-11-12. Phase A is
encryption and server identity only: Lakekeeper login stays off until Phase B.
See [Phase A TLS](#phase-a-tls) below.

The implementation follows the evidence on
[`spike/feasibility`](https://github.com/datopsis/lakehouse-integration/blob/spike/feasibility/SPIKE-FINDINGS.md).
That branch is retained unchanged. All six source commits live in
[images.lock.json](images.lock.json); changing a pin is a reviewed one-line change.
Each input is fetched by full SHA, checked against detached HEAD, built with its
own build script, and inspected after loading. Trino falls back to fetching
`refs/pull/2/head` if the SHA fetch fails, then still requires exact HEAD.

**Strict provenance is mandatory for every image.** There is no allowance for
inherited or missing labels. All six current pins pass this gate on both
architectures in this repository's PR checks. The mandatory gate checks
`org.opencontainers.image.revision` against the pin and
`io.datopsis.artifact-lock.sha256` against the exact repository artifact lock. The image
architecture must match its native runner: `amd64` / `x86_64` or `arm64` / `aarch64`.
PostgreSQL and nginx-ubi use `artifacts/locks/<architecture>.json`; Lakekeeper, SeaweedFS, and
Trino each use their shared repository lock, with architecture-specific artifacts.
Sail hashes its shared Sail/RPM lock pair and selects native artifacts too.
Runtime probes still collect evidence when all images built, but cannot turn a
failed provenance gate green. `reports/builds.json` records each image separately.

The Trino pin is a **deliberate pre-release exception for testing only**: it is the
head of draft PR #2, whose vulnerability gate remains blocked by unfixed-upstream
jars. This test makes **no security claim about Trino**, does not replace its
security gate, and does not authorize release or modify the jars.

## Assertions

| Test | Required evidence |
| --- | --- |
| T1 | CREATE SCHEMA/TABLE, INSERT/SELECT, UPDATE/DELETE; exact rows, affected counts, Iceberg v2/Parquet, four snapshots with `append, append, overwrite, delete`, matching ancestor history |
| T2 | PyIceberg reads exact Trino rows before and after mutations |
| T3 | Trino reads exact PyIceberg-written rows |
| T4 | Every table's current metadata, data, and delete files exist in the S3 bucket; exact catalog table rows exist in PostgreSQL |
| T5 | `compose down` keeps volumes; `up` replaces all ten IDs (eight services and both proxies); fresh clients reread every table; a new write is read back |
| T6 | Anonymous S3 and wrong S3 secret return specific 403 errors; missing encryption key prevents Lakekeeper startup; wrong PostgreSQL password prevents migration (over verify-full TLS) |
| T7 | Non-root, read-only roots, dropped capabilities, no-new-privileges, internal network, no published ports; each proxy shares only its application's network namespace; S3 cannot read PostgreSQL secrets; Sail receives only its own AWS env file; exact read-only mounts give each service only its own private key |
| T8 | SIGKILL all ten containers (eight services and both proxies) after three acknowledged 16-row INSERTs; exact rows and four snapshots (CREATE plus three INSERTs) after restart on the same volumes. SIGKILL PostgreSQL, Lakekeeper (with its proxy, one namespace), volume, and filer during continuous INSERTs; retain every acknowledged batch, require ambiguous batches fully visible or absent, verify snapshot counts/chains and fresh PyIceberg/Trino reads, and require a new successful write after each restart. Report recovery seconds per component. |
| T9 | No-key remote-signing client retained across recreation; serial exact-row controls and deterministic concurrent-initialization canary with unsigned HEAD 403 / GET AccessDenied evidence |
| T10 | Sail CREATE/INSERT, exact Trino/fresh-PyIceberg reads after INSERT/UPDATE/DELETE; Sail reads Trino/PyIceberg tables, with passive REST/S3 credential evidence (catalog loopback hop and the S3 gateway's signing identity) |
| T11 | Six small INSERTs; optimize reduces data-file count with exact rows in Trino/PyIceberg/Sail; expire all noncurrent snapshots, reject expired time travel, verify old files deleted in S3; remove a planted orphan while preserving every manifest reference; default seven-day retention refusals; repeat exact reads and S3 references after T5 and every T8 crash |
| T12 | Trino add/rename/drop/widen/nested-add; exact schemas and old/new rows after every DDL and INSERT in Trino, fresh-process PyIceberg and fresh-session Sail; six historical snapshots by ID and timestamp, with historical schemas after evolution; exact Sail failure canaries only where measured |
| TLS | Exact listener inventory per namespace; plaintext refused on every exposed listener; loopback backends refuse other containers; SeaweedFS mTLS required; real clients refuse wrong-CA, wrong-hostname and expired certificates; SeaweedFS exact-outcome canaries. Exposure checks repeat after T5 and T8 |
| Canary | Default Trino encoding, INSERT/UPDATE/DELETE, then PyIceberg read; only the exact known Arrow decoder error is an expected failure |

The main Iceberg catalog sets
`parquet.writer.delta-length-byte-array-encoding-enabled=false`. The separate
`canary` catalog omits that property. Its mutation scan must contain positional
delete files. A successful exact-row read emits a CI notice and job-summary entry
that upstream fixed the decoder and the setting can be revisited. Any other
error, wrong rows, or missing test fails. The canary is also reread after restart;
its specific expected decoder failure is the only exception to reading every
table successfully with PyIceberg. Trino must read all four tables successfully.
Both nginx-ubi proxies are recreated with their applications too.
Sail is recreated too and reads all four tables, then writes another row read
exactly by Trino and fresh PyIceberg.

Static S3 credentials are explicit: Trino credential vending is off; PyIceberg
sends `X-Iceberg-Access-Delegation: client-managed`. S3 credentials and PostgreSQL
passwords are enabled. Lakekeeper login is off, a known gap acceptable **only on
the private test network**. Trino uses its documented isolated-test insecure
mode with no published listener. See [SECURITY.md](SECURITY.md).

T5 covers graceful recreation; T8 tests crash durability under container SIGKILL
on one host at the reviewed pins. **A container SIGKILL is not host power loss:**
the host page cache can survive. There is no fsync or disk-cache qualification,
and no host-loss evidence. These tests do not prove production readiness,
login/authorization, replication, backup recovery, load, upgrades,
or general concurrent remote-signing recovery.

T9 isolates remote signing from the main path. The restart investigation found a
PyIceberg/Fsspec concurrency bug: FileIO initialization temporarily removes the
signer callback from a shared S3 client, allowing an unsigned request to escape.
The same live table works across recreation when initialization is serialized.
T9 forces the real callback gap and accepts only unsigned HeadObject 403 followed
by GET AccessDenied, then requires exact-row recovery. A successful signed canary
emits a notice; any other failure fails the job. See the
[draft report and reproduction](docs/known-issues/remote-signing.md); nothing was
filed upstream. Reloading a table or starting a fresh process is not a general
fix for the race. Remote signing remains OFF the main data path.

T11 alone uses the generated `maintenance` test catalog with
`iceberg.expire-snapshots.min-retention=0s` and
`iceberg.remove-orphan-files.min-retention=0s`. These are **test-only destructive
settings**, never production recommendations. The normal `iceberg` catalog keeps
both seven-day defaults; T11 requires the exact default rejection for each
procedure before invoking it through the maintenance catalog.

## Phase A TLS

Every hop uses TLS 1.2/1.3 with a per-run CA and server verification,
subject to the SeaweedFS residual risk below: Trino HTTPS (ingress, internal,
REST and S3 clients), PyIceberg, PyArrow, botocore and fsspec, PySpark to Sail through its
proxy, Lakekeeper through its proxy, Lakekeeper (serve **and** migrate) to
PostgreSQL with `verify-full`, Lakekeeper and Sail to S3, and SeaweedFS HTTPS and
gRPC mutual TLS between roles. Each repository's documented TLS profile is used at
its pinned commit; the two proxies mount the pinned nginx-ubi Lakekeeper and Sail
profiles unmodified. Sail uses its documented `SSL_CERT_FILE` and the pinned
sail-ubi retry/reattach client policy.

An interim SeaweedFS trust setting is an owner-accepted residual risk for
a known SeaweedFS limitation, reported upstream (see seaweedfs-ubi PR #81).
Exact-outcome canaries fail the gate if the behavior changes.

The cross-service TLS checks prove an exact listener inventory, plaintext refusal
on every exposed listener, loopback backends unreachable from other containers,
SeaweedFS mTLS enforcement, per-service key isolation, and that real clients refuse
wrong-CA, wrong-hostname and expired certificates. Details and limits are in
[ARCHITECTURE.md](docs/ARCHITECTURE.md#phase-a-tls-as-built) and
[TLS-PLAN.md](docs/TLS-PLAN.md). Rotation, revocation and production PKI are not
claimed.

## Run locally

Use a disposable **Linux x86_64 or aarch64** machine with Python 3.11 or 3.12, Git, Bash,
Docker CLI + Compose v2, Podman, RPM/GnuPG tooling, OpenSSL, tcpdump, util-linux `nsenter`, and sudo. Repository-owned builds
use both Docker and Podman; the runner must reach its private bridge IPs.
macOS/Windows users should run inside a Linux VM matching their native CPU,
without publishing listeners. QEMU and cross-architecture emulation are not supported.
Allow several GB of disk and memory (Trino is capped at 3 GiB). No GitHub secrets
or prebuilt Datopsis images are required. Builds download locked upstream inputs.

```bash
set -euo pipefail
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.txt
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/zizmor --offline --persona pedantic .github/workflows
.venv/bin/python -m unittest discover -s tests -v
bash integration/run.sh
```

Docker is the CI runtime. For a Podman runtime on Linux, expose a **local rootful
Podman API socket** to the Docker CLI/Compose compatibility client (not TCP):

```bash
set -euo pipefail
sudo systemctl start podman.socket
sudo env DOCKER_HOST=unix:///run/podman/podman.sock bash integration/run.sh
```

Keep Docker CLI/Compose installed: the owning repositories choose their build
runtimes, and this harness uses the Docker-compatible inspect/Compose API.
The Podman socket path is a local alternative, not yet CI-qualified; API or
hardening differences must fail, never relax the assertions. Rootless private
network bridge routing from the host is not supported by this runner.

The runner generates fresh credentials under ignored `.runtime/`, mounts only
service-specific files, retains those credentials and four named volumes during
T5 and T8, and removes the stack and volumes at final cleanup. It temporarily adds and
then removes a marked block in `/etc/hosts`. Raw local logs may contain secrets;
only `reports/sanitized/` is eligible for CI upload. T9 records REST signer
requests/responses and S3 headers in `remote-signing.jsonl`; SeaweedFS verbose
auth logs and GET error XML explain the denial. Fixture keys, signatures and
bearer tokens are redacted. Cleanup fails closed if it cannot redact. Inspect that directory for `builds.json`, `results.json`, and logs.

T8 adds
`crash-journal.jsonl` (attempts, acknowledgements, query IDs, kill events and recovery)
and `crash-*-reader.log` (fresh-process exact read evidence). Recovery time runs
from the kill command through a newly started successful INSERT and exact reads
by both clients, bounded at 180 seconds per component. In-flight outcomes are
reported, not required to commit or abort; partial batches, lost acknowledged
data, corrupt/unreadable tables, and failure to recover fail the test. See the
[architecture](docs/ARCHITECTURE.md) for injection and settlement details.

Run from a clean workspace. Before rerunning, after ensuring the stack has been
removed, delete only this harness's `.sources/`, `.runtime/`, and `reports/`
(`.runtime/` contains root-owned secret files). Never reuse these credentials.

Regenerate the dependency lock deliberately, then reinstall and review the diff:

```bash
set -euo pipefail
.venv/bin/pip-compile --generate-hashes --allow-unsafe --strip-extras \
  --output-file requirements.txt requirements.in
.venv/bin/pip install --require-hashes -r requirements.txt
```

`requirements.in` pins direct dependencies; `requirements.txt` pins and hashes
the complete resolved set, including lint/lock tools. CI installs with hashes.
Never run Python with `-O` or `PYTHONOPTIMIZE`: assertions are the test contract.

## CI

One workflow runs on pull requests, weekly Mondays at 06:23 UTC, and manual
dispatch. `Integration (amd64)` on `ubuntu-24.04` and `Integration (arm64)` on
`ubuntu-24.04-arm` run in parallel, each with a 45-minute cap and fail-fast disabled.
Both assert `uname -m` and run the same builds, strict provenance, T1–T12, T8 crash
scenarios, encoding canary, remote-signing canary and the cross-service TLS checks
without exemptions. The
required check named exactly `Integration` waits for both matrix jobs and fails
unless both succeed (including skipped/cancelled outcomes). All actions use full SHAs.
Artifacts are named `lakehouse-<architecture>-<run_id>-<attempt>` and include
`runner-uname.txt` plus image architecture, lock path/hash, revisions and labels
in `builds.json`. Actions job start/end timestamps give each architecture's wall
time and runner minutes; parallel execution overlaps wall time but consumes both
jobs' runner time.
The integration and upstream-comparison jobs have only `contents: read`.
The separate issue job gets `issues: write` only on scheduled failures (either architecture or upstream reporting), checks out
no code, and opens/updates the single issue **Weekly lakehouse integration failed**
with the run link. The built-in GitHub token is sufficient. The upstream job only
reports each pin versus its repository's `main` in the job summary; it never
commits or opens PRs. A newly introduced schedule takes effect after merge to main.

See [architecture](docs/ARCHITECTURE.md), [roadmap](docs/ROADMAP.md), and
[changelog](CHANGELOG.md). CI artifacts expire after 14 days; retain required
review evidence before that expiry. A green badge alone is not a security review.

## Sail qualification

Sail uses the reviewed source pin in `images.lock.json`, its own `scripts/build.sh`,
and the exact configuration/limits in that pin's `docs/ICEBERG.md`. Its provenance
label is checked against SHA-256 of `sail.lock.json` followed by `rpms.lock.json`,
exactly as its build script specifies; both input hashes are recorded. No label
allowance applies. Its Spark Connect client uses the owning repo's hash-locked
requirements in an isolated environment, preserving the main Arrow canary versions.

T10 exercises unpartitioned Iceberg v2/Parquet tables and explicit copy-on-write
UPDATE/DELETE. It does not claim merge-on-read UPDATE support (unsupported by
0.7.3) or qualify MERGE. A Sail-only `0600` environment file delivers static
`AWS_*` credentials. The unauthenticated Spark Connect listener is private, with
no published port. Lakekeeper's `sts-enabled=false` profile is unchanged.

Sail 0.7.3 hard-codes `X-Iceberg-Access-Delegation: vended-credentials`.
T10 records the real Lakekeeper response and the actual request header from the
catalog's internal loopback hop, and the S3 gateway's record of Sail's own signing
identity, in sanitized artifacts; startup alone is insufficient evidence.
The [qualified run](docs/SAIL-EVIDENCE.md) proves Sail uses its static AWS keys
successfully: Lakekeeper returns signing properties but no keys, and the trace
shows direct S3 signing with zero signer calls. T10 is a mandatory success test.
Configurable delegation was added upstream in [0c8333a](https://github.com/lakehq/sail/commit/0c8333a349e5438e4b37fe984b9e3a45befc7bff);
a future reviewed sail-ubi release containing that change can explicitly omit
vending. This integration does not patch or upgrade the pinned engine.
