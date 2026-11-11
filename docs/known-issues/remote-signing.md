# Draft upstream report: concurrent PyIceberg FileIO initialization drops remote signing

Not filed upstream. Classification **(c): client integration bug**, observed with
PyIceberg 0.12.0 and Fsspec/S3FS 2026.9.0. Remote signing remains outside the main
static-credential data path. A catalog restart is not required to trigger it.

## Observed failure and cause

The original [spike run 42953755477](https://github.com/datopsis/lakehouse-integration/actions/runs/42953755477)
failed after full stack recreation with `PermissionError: Forbidden`, caused by
S3 `HeadObject` HTTP 403. Its retained log lacks the failed request headers, so we
cannot retrospectively prove which request went unsigned. The executed spike
revision was `efb0bd64c2f8f0bdb35d7c85266c06eb5c538112`; the retained branch tip
later changed verification to a fresh process. The failed `py_read()` itself
constructed a new catalog/table in the same process; “long-lived client” did not
mean one retained Table object. It also used default delegation and supplied keys,
although its actual FileIO was remote-signing Fsspec. The explicit no-key test
below removes that ambiguity.

[Diagnostic run 42967416579](https://github.com/datopsis/lakehouse-integration/actions/runs/42967416579)
reproduced the same unsigned `HeadObject` 403 **before** recreation with explicit
`X-Iceberg-Access-Delegation: remote-signing` and no client S3 keys. Adjacent requests
were signed and successful. The same retained table subsequently read exact rows
after recreation. This rules out restart as a necessary trigger.

The source-level mechanism is:

1. [PyIceberg `_s3()`](https://github.com/apache/iceberg-python/blob/pyiceberg-0.12.0/pyiceberg/io/fsspec.py#L186-L241)
   configures Botocore `UNSIGNED`, creates/reuses `S3FileSystem`, then unregisters
   and registers `before-sign.s3` handler ID 1925. Its FileIO cache is per thread.
2. [Fsspec's instance cache](https://github.com/fsspec/filesystem_spec/blob/2026.9.0/fsspec/spec.py#L90-L110)
   omits the thread ID for synchronous wrappers around async filesystems. Multiple
   PyIceberg threads therefore get the same S3FS client and event emitter.
3. A read during the unregister/register gap has neither the remote callback nor
   an AWS signer. No signing HTTP request is made; S3 receives no Authorization,
   X-Amz-Date or X-Amz-Content-Sha256. SeaweedFS denies anonymous access.
4. When initialization finishes, signed reads work again without replacing the
   table, catalog, storage credentials, or server. Reloading a catalog alone does
   not eliminate the concurrency hazard; a fresh process can encounter it too.

The initial diagnostic's unsigned request ID was
`18E6E760247753183CAB07B4` (05:45:01 UTC). `remote-signing.jsonl` records HEAD 403
with only User-Agent and SDK headers, with no matching signer call. SeaweedFS's
`services-before-recreation.log` records anonymous (`"-"`) HEAD 403 for that exact
object at 05:45:01.668814683Z, between authenticated reads by `lakehouse`.

## Deterministic reproduction (T9)

Run the normal integration workflow on `ubuntu-24.04` amd64, or follow README's
hash-locked install and `bash integration/run.sh` on a disposable amd64 host.
No external credentials are needed. See `integration/remote_signing.py`.

- Create and mutate the Trino table with the existing encoding setting. Require
  exact `(1, alpha), (2, updated)` rows and positional delete files.
- Load a no-key remote-signing Table and read it. Retain its catalog, Table and
  filesystem across `compose down` / `up`, keeping volumes and fixture keys.
  Assert all seven container IDs change. Read the same table again.
- Use a single-worker executor only for the serial control reads. The existing
  static-path tests retain their executor. This is an experiment control, not a
  claimed general workaround or a skipped concurrent assertion.
- Start another thread initializing a real `FsspecFileIO` with the same properties.
  Wrap the existing emitter's `unregister` to pause **after the real upstream call**
  and before upstream registers the replacement. Do not unregister anything in
  test code, strip headers, replace the signer, or fake an HTTP response.
- Read a positional-delete Parquet file through the original FileIO while the
  initializing thread is paused. Require exact `PermissionError("Forbidden")`,
  caused by `ClientError`, operation `HeadObject`, status 403, code `403`.
- GET the same object through that unsigned filesystem to capture SeaweedFS's
  XML reason: status 403, code `AccessDenied`, message `Access Denied.`. HEAD cannot
  carry that body. Require zero signer calls and absent Authorization on both.
- Release initialization and require identical shared filesystem identity. Reread
  exact rows with the original table, a reloaded table and a new catalog. All
  signing/storage properties (excluding auth-manager object identity) must match.

Only that fully corroborated failure is expected. Any different exception, error
code, operation, status, signed failure, missing evidence or wrong rows fails CI.
If upstream removes the gap or stops sharing the filesystem, successful signed
reads plus exact recovery rows produce an `upstream-fixed` result, a GitHub notice
and a job-summary notice. Barrier timeouts fail. The canary remains mandatory.

[Deterministic amd64 run 42968251506](https://github.com/datopsis/lakehouse-integration/actions/runs/42968251506)
passed all gates. T9 took 12.18 seconds after readiness; its canary recorded
`shared_filesystem=true`, `signer_calls_in_gap=0`, HEAD 403 and GET AccessDenied.
SeaweedFS's GET request ID `18E6E7D86777F04CC958991F` matches its server XML log.
The same retained table passed before recreation, after recreation, and after
releasing the callback gap. Reloaded table and new catalog controls also matched
exact rows. All seven IDs changed; T1–T7 and the encoding canary passed.

[Retained evidence excerpts](evidence/42968251506.json) include run/job metadata,
all assertions, DNS, selected signer requests/responses, unsigned requests and
the matching server error. Full sanitized logs remain in the run artifact.
Integration took 4m52s, Upstream commits 7s; the scheduled-only issue job did not
run on this PR. An earlier diagnostic run 42966939106 failed because an
unsupported command-line verbosity flag prevented S3 startup; that was corrected
to upstream's `WEED_V` environment flag, with the image entrypoint preserved.

## Hypotheses and discriminating evidence

| Hypothesis | Test / outcome |
| --- | --- |
| Restart invalidates signer endpoint, token or table config | Same retained table works after recreation with unchanged config; no token is configured. Forced failure makes zero signer calls. Releasing initialization restores reads without a refresh. |
| Changed Host/IP/endpoint corrupts canonical signing | DNS is recorded before/after; request URI/Host remains `s3:8333`. Signed controls pass after recreation. The failing request is unsigned, so it has no canonical signature to mismatch. |
| Credential expiry or clock skew | No client credentials, STS token or catalog token. Successful signed controls use the fixture access-key scope and require signature timestamp within 60 seconds of SeaweedFS's HTTP Date. Failures contain no timestamp or signature. |
| Lakekeeper reloads stored credentials incorrectly | Its existing warehouse signs successful operations after recreation using the retained access key; the same Table reads again after releasing the barrier. The failing interval never calls Lakekeeper. |
| SeaweedFS identity reload rejects valid signatures | Signed reads succeed on the same recreated gateway immediately around the forced failure. The GET XML says AccessDenied for an unsigned request; verbose server logs identify anonymous versus `lakehouse` requests. |
| Concurrent client initialization | Real callback removal is the controlled variable. Pausing there produces unsigned HEAD/GET denial; releasing it restores signed reads. |

## Version pins

Image pins remain exclusively in [images.lock.json](../../images.lock.json); no
image was changed for this investigation. All four strict provenance checks pass.
The current Lakekeeper/SeaweedFS wrappers contain the same binaries as the spike:

| Component | Version / identity |
| --- | --- |
| PyIceberg | 0.12.0 |
| PyArrow | 25.0.1 |
| Fsspec / S3FS | 2026.9.0 / 2026.9.0 |
| aiobotocore / Botocore | 3.10.0 / 1.43.117 |
| aiohttp | 3.14.5 |
| Lakekeeper | 0.13.4; source `9bd377162345b64a716f0a4fcffe4e7e7f3c7534`; binary SHA-256 `52cdaa0be3724158ce7943f211fcff09a1ae451b5e88916a42b367bdaf1fd705` |
| SeaweedFS | 4.53 large_disk; source `4ab66fb76da83700739f5839e62fcaf15fb7d02a`; binary SHA-256 `4b51c35ab81fd0913e2bf05db6771f1c7c82959d8b3129b54686a9a4998dd813` |
| Trino / PostgreSQL | 484 development / 18.6; exact image revisions and lock hashes in run `builds.json` |

`requirements.txt` hashes the full Python dependency set, including the restored
PyIceberg S3FS extra. Existing dependency versions were not changed.

## Scope and follow-up

This establishes a client-side race, not a requirement to reload tables following
Lakekeeper restart. It does not establish that all historical 403s had this cause,
qualify arbitrary concurrent remote-signing use, or prove TLS/login/authorization,
crash durability, ARM64, or production readiness. Keep the main path on explicit
client-managed static credentials. An upstream fix needs review and a canary
notice; do not quietly remove the expected failure or file this draft automatically.
