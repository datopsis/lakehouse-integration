# Lakehouse integration

One amd64 integration gate for the five Datopsis image repositories: Trino queries
Iceberg v2 / Parquet through Lakekeeper's REST catalog, PostgreSQL stores catalog
metadata, and separated SeaweedFS master/volume/filer/S3 roles store table objects.
Sail is the second query engine; PyIceberg is an independent client. Nothing is published to a host port.

The implementation follows the evidence on
[`spike/feasibility`](https://github.com/datopsis/lakehouse-integration/blob/spike/feasibility/SPIKE-FINDINGS.md).
That branch is retained unchanged. All five source commits live in
[images.lock.json](images.lock.json); changing a pin is a reviewed one-line change.
Each input is fetched by full SHA, checked against detached HEAD, built with its
own build script, and inspected after loading. Trino falls back to fetching
`refs/pull/2/head` if the SHA fetch fails, then still requires exact HEAD.

**The initial Lakekeeper and SeaweedFS pins fail strict provenance.** There is no
allowance for inherited or missing labels. The mandatory gate checks
`org.opencontainers.image.revision` against the pin and
`io.datopsis.artifact-lock.sha256` against the exact repository artifact lock.
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
| T5 | `compose down` keeps volumes; `up` replaces all eight IDs; fresh clients reread every table; a new write is read back |
| T6 | Anonymous S3 and wrong S3 secret return specific 403 errors; missing encryption key prevents Lakekeeper startup; wrong PostgreSQL password prevents migration |
| T7 | Non-root, read-only roots, dropped capabilities, no-new-privileges, internal network, no published ports; S3 cannot read PostgreSQL secrets; Sail receives only its own AWS env file |
| T10 | Sail CREATE/INSERT, exact Trino/fresh-PyIceberg reads after INSERT/UPDATE/DELETE; Sail reads Trino/PyIceberg tables, with passive REST/S3 credential evidence |
| Canary | Default Trino encoding, INSERT/UPDATE/DELETE, then PyIceberg read; only the exact known Arrow decoder error is an expected failure |

The main Iceberg catalog sets
`parquet.writer.delta-length-byte-array-encoding-enabled=false`. The separate
`canary` catalog omits that property. Its mutation scan must contain positional
delete files. A successful exact-row read emits a CI notice and job-summary entry
that upstream fixed the decoder and the setting can be revisited. Any other
error, wrong rows, or missing test fails. The canary is also reread after restart;
its specific expected decoder failure is the only exception to reading every
table successfully with PyIceberg. Trino must read all four tables successfully. Sail is recreated too and reads all
four tables, then writes another row read exactly by Trino and fresh PyIceberg.

Static S3 credentials are explicit: Trino credential vending is off; PyIceberg
sends `X-Iceberg-Access-Delegation: client-managed`. S3 credentials and PostgreSQL
passwords are enabled. Lakekeeper login is off, a known gap acceptable **only on
the private test network**. Trino uses its documented isolated-test insecure
mode with no published listener. See [SECURITY.md](SECURITY.md).

This proves a small, single-host, graceful stop/recreate path at reviewed pins.
It does not prove production readiness, TLS/login/authorization, crash durability,
replication, backup recovery, load, ARM64, upgrades, or remote-signing recovery.
The spike's long-lived remote-signing reader failed with 403 after restart;
that remains a [roadmap item](docs/ROADMAP.md).

## Run locally

Use a disposable **Linux x86_64** machine with Python 3.11 or 3.12, Git, Bash,
Docker CLI + Compose v2, Podman, RPM tooling, and sudo. Repository-owned builds
use both Docker and Podman; the runner must reach its private bridge IPs.
macOS/Windows users should run inside an amd64 Linux VM, not publish listeners.
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
T5, and removes the stack and volumes at final cleanup. It temporarily adds and
then removes a marked block in `/etc/hosts`. Raw local logs may contain secrets;
only `reports/sanitized/` is eligible for CI upload. Cleanup fails closed if it
cannot redact. Inspect that directory for `builds.json`, `results.json`, and logs.

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
dispatch, on `ubuntu-24.04` amd64 with a 30-minute cap. All actions use full SHAs.
The integration and upstream-comparison jobs have only `contents: read`.
The separate issue job gets `issues: write` only on scheduled failures, checks out
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
T10 records the real Lakekeeper response, the actual request header and S3 signing
traffic in sanitized artifacts; startup alone is insufficient evidence.
Runtime qualification is pending the PR's Actions run. Configurable delegation
was added upstream in [0c8333a](https://github.com/lakehq/sail/commit/0c8333a349e5438e4b37fe984b9e3a45befc7bff);
a future reviewed sail-ubi release containing that change can explicitly omit
vending. This integration does not patch or upgrade the pinned engine.
