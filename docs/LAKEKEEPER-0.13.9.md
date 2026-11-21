# Lakekeeper 0.13.9 pin investigation (PR #23)

Classification: **(a), a legitimate upstream response-contract fix requiring a
fixture assertion update**. Keep the Lakekeeper 0.13.9 pin, STS disabled, static
engine keys, existing locations and persistence configuration.

## Original failure evidence

[Run 44814967572](https://github.com/datopsis/lakehouse-integration/actions/runs/44814967572)
failed on both native architectures. Downloaded both `lakehouse-<arch>-44814967572-1`
artifacts and inspected `results.json`, `probe.log`, service logs and the Actions
failed-step logs. Artifact line references below use `probe.log` from amd64:

- Lines 289–303: `T10_sail` fails with `KeyError: 'storage-credentials'` at
  `sail_probe.py:201`, before its CREATE TABLE queries run.
- Lines 304–345: T4's 404 URL ends in `/tables/from_sail`. This table was never
  created; the error is not evidence of a table lost on restart.
- Lines 626–629: after full recreation, Trino reads the exact `from_trino`,
  `from_python` and `encoding_canary` rows and acknowledges the new Python-table
  write. The preceding T9 result also records exact remote-signed reads across
  recreation. Then `sail_client.py` fails with
  `TABLE_OR_VIEW_NOT_FOUND ... integration.from_sail` (lines 633–659).
- T8 cannot prepare its crash manifest because `from_sail` does not exist.
  The crash scenarios were therefore not qualified by this failed run.
- Both `results.json` files say `TLS_certificate_negatives.status = pass`, as
  well as passing exposure checks before/after recreation and after the failed
  crash probe. The certificate refusal lines are expected success evidence,
  printed in the combined failing integration step; they are not TLS failures.

Both architectures have the same first failure and missing-table cascade.

## Upstream cause and safety

[0.13.6 release notes](https://github.com/lakekeeper/lakekeeper/releases/tag/v0.13.6)
include “don't vend a credential-less storage-credentials entry”. The exact change
is [29c53e3204cd0c620271b3fb3abbf2d0d1151f0a](https://github.com/lakekeeper/lakekeeper/commit/29c53e3204cd0c620271b3fb3abbf2d0d1151f0a)
([#1923](https://github.com/lakekeeper/lakekeeper/pull/1923)). It changes table
load/create/credential responses, not just generic tables. With STS disabled,
endpoint/region properties alone no longer produce a scoped credential entry.
Such a key-less entry can override a client's working static credentials and
cause unsigned storage requests. The properties and remote-signing hints remain
in top-level `config`; a client without signer support still needs its own keys.
See upstream's `TableConfig::storage_credentials` and
`S3Profile::generate_table_config` at tag `v0.13.9`.

The old T10 assertion required exactly the response shape this upstream fix
removed. The new assertion requires **absence** of `storage-credentials`, absence
of all three S3 credential keys in `config`, and the same exact signer hints.
It rejects null, empty and credential-less entries too. Unit cases reject leaked
keys and changed signing hints. Passive Sail-attributed capture must still prove
its vending request, zero signer POSTs, and Sail's own static signing identity.
All CREATE/INSERT/UPDATE/DELETE, exact rows, object existence, PostgreSQL catalog
rows, fresh readers, full recreation, new writes and crash assertions remain.

## Other candidate changes reviewed

Reviewed release notes for 0.13.5–0.13.9 and the
[46-commit comparison](https://github.com/lakekeeper/lakekeeper/compare/v0.13.4...v0.13.9).
API cache isolation/private response headers in `cc162fea205c` do not delete
catalog rows. S3 confinement (`2882e8446555`, `a6e74469d8bb`) limits signing and
metadata cleanup to a table's location. Deprecated data-path properties are
refused by `38330d54f449`; this fixture does not set them. Soft-deletion expiry
in inactive warehouses and commit refusal for concurrently soft-dropped tables
are covered in the 0.13.8/0.13.9 notes; the main fixture neither drops its test
tables nor deactivates its warehouse. The comparison adds no SQL migration files;
the migration module diff adds a foreign-key test. Location uniqueness already
exists, and the original failure occurs before Sail proposes its table location.
There is no evidence here justifying a location, cache, expiry or deployment
configuration workaround, nor an upstream regression issue.

This is a fresh-volume fixture, not an in-place upgrade/migration qualification.

## Corrected-branch evidence

[Run 44957439454](https://github.com/datopsis/lakehouse-integration/actions/runs/44957439454)
passed at implementation commit `76fb458d9865be5092db32d0e2727bd395849f88`.
Both native artifacts were downloaded and inspected, including `builds.json`,
`results.json`, `probe.log`, `sail-traffic.log`, `sail-s3-identities.log` and the
fresh crash-reader logs. `gh run view --log-failed` returned no failed-step logs.

| Native job | Result | Job wall time | Runtime probes |
| --- | --- | --- | --- |
| amd64 | Passed | 25m 38s | 1268.81s |
| arm64 | Passed | 22m 06s | 1093.47s |
| Required `Integration` aggregate | Passed | 4s | Both jobs succeeded |

On each architecture, all six builds and strict provenance passed. There were
zero failed probes. T10 created and mutated `from_sail`, confirmed its own static
S3 signing identity with zero signer POSTs, and recorded no `storage-credentials`
field. T4 verified objects and exact catalog rows. T5 replaced all ten container
IDs and passed fresh reads and new writes. T8 passed the all-service SIGKILL and
individual PostgreSQL/catalog/volume/filer scenarios, including exact acknowledged
rows and snapshots, independent reads and recovery writes. The 88-row TLS matrix
passed. Encoding and remote-signing race canaries retained their exact expected
failures and recovery assertions; they were not skipped or generalized.

Local validation: 42 unit tests, Ruff lint/format, offline pedantic Zizmor,
tracked YAML/JSON parsing, LF and diff whitespace checks passed. No local images
were built and no local containers were run. No settings, secrets, owning
repositories, pins beyond the original PR bump, or deployment profiles changed.
No upstream issue was filed or drafted because this is the intentional upstream
fix described above. In-place database upgrades, host power loss and production
authentication/authorization remain outside this fixture's verified scope.
