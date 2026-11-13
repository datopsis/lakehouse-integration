# Identity provider bake-off (Phase B)

## Decision

On **2026-11-13**, the owner chose **Rauthy for Phase B**, with **Keycloak as the
tested fallback**. Rauthy meets the Rust preference, passes the exercised
Lakekeeper authentication and Trino/PyIceberg native-grant tests on both native
architectures, supplies access-token group claims, and has a smaller measured
memory footprint than Keycloak. Phase B will build a hardened `rauthy-ubi` image.
Sail 0.7.3 needs an externally supplied token-file path; its native grant remains
unsupported. The choice does not imply production qualification or remove the
patching, hardening and operational work documented below.

Survey date: 2026-11-13. **Evaluation only; no IdP is qualified for the lakehouse.**
The separate [workflow](../.github/workflows/idp-bakeoff.yml) runs only through
`workflow_dispatch`, on native `ubuntu-24.04` and `ubuntu-24.04-arm`. Both run
the same assertions. It is not a dependency of the required `Integration` check.
Its documented-red evaluation does not run on pull requests.
The Integration workflow, login setting, image locks and source pins are unchanged.

## Approved TLS path and evaluation scope

The owner confirmed on this PR's follow-up that Phase A's design was approved on
**2026-11-12**: Lakekeeper binds **127.0.0.1:8182**, and the datopsis/nginx-ubi
Lakekeeper profile serves **verified TLS on 8181** in the same network namespace.
This supersedes the earlier interpretation of the undecided exception in
[TLS-PLAN.md](TLS-PLAN.md). The loopback hop is an explicitly approved plaintext
exception; tokens are never sent in plaintext across the container bridge.

The evaluation pins nginx-ubi to **`9ef9e822c6b5e508cebef2adff3bb647a206773c`** and
uses its [Lakekeeper profile](https://github.com/datopsis/nginx-ubi/blob/9ef9e822c6b5e508cebef2adff3bb647a206773c/examples/profiles/lakekeeper/nginx.conf)
unchanged. The owner's build/lock verification runs natively, and image revision,
architecture and lock-digest labels must match. The main Integration workflow,
image lock and authentication settings are unchanged. This is an evaluation-only
proxy input, explicitly authorized separately from the main image pins.

Each IdP gets its own disposable authenticated Lakekeeper database and catalog,
with the real pinned 0.13.4 binary, `OPENID_AUDIENCE=lakekeeper`, subject `sub`,
and roles `groups`. The proxy gets its leaf certificate/key; Lakekeeper gets only
the public CA. Tests inspect the shared namespace and loopback listener and require
bridge connections to backend/metrics ports to fail. Frontend plaintext, wrong CA
and wrong hostname must be rejected. All bearer-bearing HTTP calls use verified TLS.

The harness now implements real table list/read, human-token acceptance, valid and
invalid-token checks, and JWKS rotation against Lakekeeper. The wrong-audience
case keeps the genuine token, key and issuer fixed and changes only Lakekeeper's
expected audience, with passing controls before and after. Expiry uses a genuine
IdP-signed token, waits beyond its expiry plus the verifier's 60-second clock-skew
allowance, and requires a fresh-token control. It never edits `exp` and mistakes a
signature failure for expiry enforcement. A restart after the separately recorded
rotation assertion isolates the later expiry test; it cannot turn rotation failure
into a pass.

Trino's isolated query interface, Sail's isolated Spark Connect interface and the
existing S3 test profile remain as in the main fixture; no IdP token is sent over
those query interfaces. Native Sail client-credentials support is not invented:
its no-token failure and a separate externally supplied-token read are recorded.
The latter is not counted as a native-grant pass.

## Reproducible upstream inputs

Latest stable releases were resolved using each repository's releases API;
OCI indexes were fetched from the project's official registry and SHA-256 hashed.
All runtime pulls use the digest, never a moving tag. Both platforms are in every
index. These evaluation references are separate from the main image lock.

| IdP | Release | Official upstream image index digest |
| --- | --- | --- |
| Kanidm | [1.12.0](https://github.com/kanidm/kanidm/releases/tag/v1.12.0) | `docker.io/kanidm/server@sha256:71b6ff5a9c9c32b632894d8acef5a2afc77941b35a0aa95dcee959fe688d5ce9` |
| Rauthy | [0.37.2](https://github.com/sebadob/rauthy/releases/tag/v0.37.2) | `ghcr.io/sebadob/rauthy@sha256:d733b7580f53c1601c286b5504853b2774e70245f5f9427d9bcda32496b753ee` |
| Keycloak | [26.8.2](https://github.com/keycloak/keycloak/releases/tag/26.8.2) | `quay.io/keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0` |

All IdP calls use HTTPS with a generated per-run CA, hostname verification and
no automatic redirects. Human login uses scripted HTTP, S256 PKCE, state and
nonce checks; it does not use the password grant as a substitute. Keycloak's
bootstrap administration separately uses its administrative password grant.
CA keys, leaf keys, passwords, client secrets, authorization codes and bearer
tokens are generated per run and excluded from artifacts. Decoded claims concern
only synthetic identities. No GitHub secrets, permissions or settings are changed.

Rauthy's internal Hiqlite ports 8100 and 8200 also use this CA and verified TLS.
Its upstream [`CLIENT_CREDENTIALS_MAP_SUB=true`](https://github.com/sebadob/rauthy/blob/v0.37.2/src/service/src/token_set.rs)
setting maps the client ID to the
machine-token subject; by default that grant omits `sub`. Keycloak clients include
the built-in `basic` scope so machine tokens also contain a subject. These are
provider configuration requirements, not client-side token rewriting.
Keycloak's single-node fixture uses Narayana's upstream
[MBeanProcessId](https://github.com/jbosstm/narayana/blob/7.3.4.Final/ArjunaCore/arjuna/classes/com/arjuna/ats/internal/arjuna/utils/MBeanProcessId.java)
through `JAVA_OPTS_APPEND`, replacing the default socket-based process identifier.
This avoids its otherwise-unnecessary plaintext loopback reservation; it does not
disable transactions or recovery. Listener enumeration must match the configured
TLS ports exactly, excluding Docker's internal DNS stub. Each application port
must accept the generated CA/hostname and reject unknown CAs, wrong hostnames and
anonymous plaintext requests. A TLS fatal decode-error alert is a rejection.

## Runtime comparison

Native [run 43378071591](https://github.com/datopsis/lakehouse-integration/actions/runs/43378071591), harness revision
`398f50e6fd6d1e41e08f735802eb964d69dc30c0`. **PASS** means the exact named assertion passed;
**FAIL** records an observed failure, including client capability gaps. **N/T**
means the provider-specific diagnostic was not tested for that provider. Externally
obtained tokens are separate controls and never count as native-grant passes.
All list/read passes require exactly `bakeoff.sample` and rows
`[{"id":1,"label":"alpha"},{"id":2,"label":"beta"}]`.

| Assertion | Kanidm amd64 | Kanidm arm64 | Rauthy amd64 | Rauthy arm64 | Keycloak amd64 | Keycloak arm64 |
| --- | --- | --- | --- | --- | --- | --- |
| Startup, provisioning and discovery | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| IdP verified TLS; CA/hostname/plaintext negatives; listeners | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Approved Lakekeeper proxy TLS and loopback isolation | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Seed and read exact two-row table | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Client-credentials endpoint returns token | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Client-credentials token accepted by Lakekeeper | [FAIL][amd64] | [FAIL][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Trino 484 native grant + list/read | [FAIL][amd64] | [FAIL][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| PyIceberg 0.12 native grant + list/read | [FAIL][amd64] | [FAIL][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Sail 0.7.3 native grant + list/read | [FAIL][amd64] | [FAIL][arm64] | [FAIL][amd64] | [FAIL][arm64] | [FAIL][amd64] | [FAIL][arm64] |
| Human authorization code + S256 PKCE | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Human token accepted by Lakekeeper | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Valid token accepted | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Wrong audience rejected | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Genuinely expired token rejected, fresh control accepted | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Different signing key rejected | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Unsigned/alg=none rejected | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| New signing key published in IdP JWKS | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Valid new token accepted by live Lakekeeper after rotation | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Groups in human access token | [FAIL][amd64] | [FAIL][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Groups in human ID token | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Startup/RSS/storage measured | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Custom service-account RFC 8693 exchange | [PASS][amd64] | [PASS][arm64] | [N/T][amd64] | [N/T][arm64] | [N/T][amd64] | [N/T][arm64] |
| Exchanged signed token accepted by Lakekeeper | [PASS][amd64] | [PASS][arm64] | [N/T][amd64] | [N/T][arm64] | [N/T][amd64] | [N/T][arm64] |
| Trino native service-token/exchange configuration | [FAIL][amd64] | [FAIL][arm64] | [N/T][amd64] | [N/T][arm64] | [N/T][amd64] | [N/T][arm64] |
| Trino with externally exchanged token: list/read | [PASS][amd64] | [PASS][arm64] | [N/T][amd64] | [N/T][arm64] | [N/T][amd64] | [N/T][arm64] |
| PyIceberg with externally exchanged token: list/read | [PASS][amd64] | [PASS][arm64] | [N/T][amd64] | [N/T][arm64] | [N/T][amd64] | [N/T][arm64] |
| Sail with externally obtained token: list/read | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |

[amd64]: https://github.com/datopsis/lakehouse-integration/actions/runs/43378071591/job/131729200474
[arm64]: https://github.com/datopsis/lakehouse-integration/actions/runs/43378071591/job/131729200183

Durable sanitized summaries include exact errors, decoded claims, public JWKS,
source-image provenance, scan versions/counts and full-artifact SHA-256 manifests:
[amd64](idp-evidence/amd64.json), [arm64](idp-evidence/arm64.json).
Artifacts `idp-bakeoff-amd64-43378071591-1` and `idp-bakeoff-arm64-43378071591-1`
retain full scanner JSON and sanitized service logs for 14 days. The committed
summaries remain after expiry. The separate evaluation check stays red for actual
unsupported cases; no required Integration assertion was changed or waived.

The unchanged required [Integration check](https://github.com/datopsis/lakehouse-integration/actions/runs/43378071581)
passed both native architectures at this harness revision.

The table supersedes the earlier plaintext preflight and fixture-debugging runs.
The owner-approved proxy removes the former transport blocker. Earlier warehouse
lookup, Trino trust configuration and repeat-consent parsing failures were harness
bugs; they are not scored as candidate failures here.

### Decoded claims

Selected fields from the amd64 synthetic human login follow. Full decoded access
and ID claims for both CPUs are in the summaries. ID-token groups are not substituted
for API access-token groups.

Kanidm access token:

```json
{
  "iss": "https://kanidm.idp.test:8443/oauth2/openid/lakekeeper",
  "aud": "lakekeeper",
  "sub": "8c0df971-7e7d-4d81-94e3-d43d12cb7e37",
  "exp": 1794552117,
  "scope": "groups openid profile"
}
```

Kanidm ID-token groups:

```json
{
  "groups": [
    "00000000-0000-0000-0000-000000000035",
    "idm_all_persons@kanidm.idp.test",
    "00000000-0000-0000-0000-000000000036",
    "idm_all_accounts@kanidm.idp.test",
    "00000000-0000-0000-0000-000000000048",
    "idm_people_self_name_write@kanidm.idp.test",
    "58477ed2-2cdc-4947-8e9d-2d0cb2b46d52",
    "lake-readers@kanidm.idp.test"
  ]
}
```

Rauthy access token:

```json
{
  "iss": "https://rauthy.idp.test:8443/auth/v1/",
  "aud": "lakekeeper",
  "sub": "2cD1oZT9FVMt4Y9aWVFGkeJJ",
  "exp": 1794551304,
  "scope": "openid profile groups",
  "roles": [
    "user"
  ],
  "groups": [
    "lake-readers"
  ]
}
```

Keycloak access token:

```json
{
  "iss": "https://keycloak.idp.test:8443/realms/bakeoff",
  "aud": "lakekeeper",
  "sub": "c68cc6a5-8268-4400-a8f0-783de1581c7e",
  "exp": 1794551446,
  "scope": "openid email profile",
  "groups": [
    "lake-readers"
  ]
}
```

## Grant and authorization-layer implications

Kanidm 1.12.0 **implements client_credentials, but Lakekeeper cannot validate its
encrypted JWE access token through the pinned OpenID authentication path**. Both
native runs obtain the JWE successfully and receive Lakekeeper HTTP **401**, with
`AuthenticationFailed: Authentication failed`. A signed human token and the signed
service-account exchange token succeed against the same catalog. This is an
observed compatibility failure, not a claim that Kanidm lacks the grant.

The [grant implementation](https://github.com/kanidm/kanidm/blob/v1.12.0/server/lib/src/idm/oauth2.rs#L1937)
encrypts `ClientAccess` into JWE. Lakekeeper's pinned
[limes JWKS authenticator](https://github.com/vakamo-labs/limes-rs/blob/dcd1bb1b5fae6f1009111276c9695f0438a344e7/crates/limes/src/jwks.rs)
validates signed JWTs and has no Kanidm JWE decryption/introspection path. Changing
an audience or scope setting cannot make this JWE a supported signed JWT.

Kanidm 1.12.0 **cannot issue group/custom claims in access tokens through its
supported claim mappings**. The configured group mapper produces groups in ID
tokens and userinfo, while the
[RFC 9068 access-token extension structure](https://github.com/kanidm/kanidm/blob/v1.12.0/proto/src/oauth2.rs#L245)
and [token construction](https://github.com/kanidm/kanidm/blob/v1.12.0/server/lib/src/idm/oauth2.rs#L2078)
exclude those extra claims from access tokens. Decoded tokens on both architectures
confirm this distinction. Group membership can control granted OAuth scopes; that
is an alternative policy signal, not a group-membership claim.

Its [service-account RFC 8693 exchange](https://github.com/kanidm/kanidm/blob/v1.12.0/book/src/accounts/service_accounts.md)
uses an API token as subject token without the OAuth client secret. The custom
HTTP exchange produces a signed JWT Lakekeeper accepts. Supplying that JWT
externally is tested separately from engines obtaining it themselves. It requires
a token-lifecycle component and is not a stock-client grant pass.

Trino's Kanidm native client-credentials test returns
`ICEBERG_CATALOG_ERROR: Cannot obtain metadata`, caused by
`org.apache.iceberg.exceptions.NotAuthorizedException: Not authorized: Authentication failed`.
PyIceberg returns `UnauthorizedError: AuthenticationFailed: Authentication failed`.
The Trino service-account diagnostic sets `oauth2.token` to the Kanidm API token,
uses the real token endpoint, and enables `oauth2.token-exchange-enabled`; it
returns the same Trino error on both CPUs. Iceberg's
[initial catalog session](https://github.com/apache/iceberg/blob/apache-iceberg-1.12.0/core/src/main/java/org/apache/iceberg/rest/auth/OAuth2Manager.java#L76)
uses that supplied token directly for bootstrap, before a usable exchanged catalog
session exists. Feeding the harness-exchanged JWT to Trino and PyIceberg produces
successful exact list/read controls. **The service-account path does not serve
these three stock clients without an additional exchange/token-lifecycle component
in the tested configuration.** This does not claim Trino has no RFC 8693 support;
it records the failed bootstrap path and the working externally exchanged control.

The pinned [Sail credential implementations](https://github.com/lakehq/sail/blob/ac4690078021cf2a5402dc5c7b38a886f1916c73/crates/sail-catalog/src/credentials.rs)
provide empty, static bearer and file bearer credentials; the configuration has no
client-credential/server-URI grant provider. The real no-token catalog request
fails with `AnalysisException: external error: Failed to load config: response
error: status code 401 Unauthorized` for **all three IdPs, including Keycloak**.
With an externally obtained valid token in its supported bearer-token file, Sail
lists and reads the exact table for all three. Thus the common failure is an
engine capability gap, not evidence against a particular IdP or the TLS harness.
PyIceberg's [built-in OAuth managers](https://github.com/apache/iceberg-python/blob/pyiceberg-0.12.0/pyiceberg/catalog/rest/auth.py)
implement client credentials, not Kanidm's service-account RFC 8693 flow; a pre-exchanged token is a separate positive control.

The disposable client configuration is reproducible in
[clients.py](../evaluation/idp/clients.py) and
[catalog.py](../evaluation/idp/catalog.py):

| Client | Native grant settings | Per-run CA trust |
| --- | --- | --- |
| Trino 484 | `iceberg.rest-catalog.security=OAUTH2`, `oauth2.credential` and `oauth2.server-uri` under `iceberg.rest-catalog`, scope `openid profile` | Public-CA JKS mounted read-only at `/opt/java/lib/security/jssecacerts`; standard JSSE discovery, no forbidden Java-option environment override |
| PyIceberg 0.12.0 | `credential`, `oauth2-server-uri`, scope `openid profile` | `ssl={"cabundle": CA_PATH}` |
| Sail 0.7.3 | No native credential/server-URI grant configuration; separate control uses `bearer_access_token_file` | `SSL_CERT_FILE` points to the public CA |

Group claims are input for Phase C, not authorization by themselves. The pinned
[Lakekeeper configuration](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/docs/docs/configuration.md)
supports an array/string roles claim, including dot-separated nested claim paths.
Its default OpenFGA backend does not automatically consume token roles; Cedar or
an explicit identity/group synchronization policy must do that work. This fixture
uses `allowall` authorization and does not qualify either backend. Bucket-wide
static S3 credentials would still bypass catalog authorization, as described in
[ARCHITECTURE.md](ARCHITECTURE.md).

## Operations and configuration as code

The measured fixture uses one IdP instance, 2 CPUs and a 2 GiB container limit.
Startup is monotonic time from `docker start` to the first verified HTTPS readiness
response, excluding image pull and subsequent API provisioning. Idle RSS is the
median of five one-second samples summing VmRSS for all container PIDs; it excludes
page cache and is not Docker's cache-adjusted memory statistic. Storage is apparent
bytes in the persistent data directory after provisioning/authentication tests.
One run per architecture is descriptive, not a benchmark distribution. Keycloak
includes first-start Quarkus augmentation and realm import in its readiness time;
Kanidm's API provisioning occurs afterward, so startup times are not equivalent
production deployment costs.

| IdP | CPU | Startup seconds | Median idle RSS MiB | Data directory MiB | Image MiB |
| --- | --- | --- | --- | --- | --- |
| Kanidm | [amd64][amd64] | 1.451 | 71.0 | 3.00 | 261.3 |
| Kanidm | [arm64][arm64] | 1.143 | 61.7 | 2.97 | 268.6 |
| Rauthy | [amd64][amd64] | 9.139 | 74.9 | 6.23 | 90.6 |
| Rauthy | [arm64][arm64] | 11.128 | 75.2 | 6.23 | 93.2 |
| Keycloak | [amd64][amd64] | 25.385 | 570.7 | 2.10 | 451.4 |
| Keycloak | [arm64][arm64] | 26.413 | 567.1 | 2.08 | 452.6 |

Keycloak contains **484 jars on each architecture**. Image sizes are Docker image
inspection totals, not compressed registry transfer sizes.

| Concern | Kanidm | Rauthy | Keycloak |
| --- | --- | --- | --- |
| Storage | Embedded database, no PostgreSQL dependency | Embedded Hiqlite/SQLite by default; PostgreSQL optional; Hiqlite cache persists even with PostgreSQL | H2 dev-file in this disposable evaluation; supported external relational DB such as PostgreSQL for production |
| CI provisioning | Supported REST API scripted here; local admin socket recovers initial credential | Native bootstrap JSON for users, groups, clients and API keys | Native realm JSON import for users, groups, clients and mappers |
| Production config as code | TOML plus SCIM/HJSON entry migrations; credentials and OAuth basic secrets cannot be asserted in migrations; API/secret-management still needed | TOML/env plus bootstrap JSON; bootstrap is initialization, not a demonstrated drift reconciler; API manages later changes | Configuration/env plus realm import and Admin API; startup import skips an existing realm, so not ongoing reconciliation |
| Backup/restore story | Scheduled online backup; offline database backup/restore or whole-volume copy; restore with the same version | Hiqlite local backups and encrypted S3 backups; retain encryption keys; restore via HQL_BACKUP_RESTORE then remove that setting; PostgreSQL uses external DB tooling | Back up production database plus configuration/keys; realm export is incomplete and not a full backup |
| HA options | Eventually consistent multiwriter replication; sticky sessions or active/passive load-balancing | Hiqlite/Raft, normally 3 or 5 nodes; persistent cache state even with PostgreSQL | Multiple nodes, shared production DB, distributed Infinispan caches; separate multi-site design available |
| Runtime backup/restore/HA tested? | No | No | No |

Sources: Kanidm [entry management](https://github.com/kanidm/kanidm/blob/v1.12.0/book/src/entry_management.md),
[backup](https://github.com/kanidm/kanidm/blob/v1.12.0/book/src/backup_and_restore.md),
[replication](https://github.com/kanidm/kanidm/blob/v1.12.0/book/src/repl/readme.md);
Rauthy [bootstrap](https://github.com/sebadob/rauthy/blob/v0.37.2/book/src/config/bootstrap.md),
[backup](https://github.com/sebadob/rauthy/blob/v0.37.2/book/src/config/backup.md),
[HA](https://github.com/sebadob/rauthy/blob/v0.37.2/book/src/config/ha.md);
Keycloak [database](https://github.com/keycloak/keycloak/blob/26.8.2/docs/guides/server/db.adoc),
[import/export limitations](https://github.com/keycloak/keycloak/blob/26.8.2/docs/guides/server/importExport.adoc),
[HA documentation](https://github.com/keycloak/keycloak/tree/26.8.2/docs/guides/high-availability).

## Supply chain and future UBI 9 work

**No hardened images or source builds of the IdPs were made.** UBI 9 source-build
success with pinned toolchains is **not verified for any candidate**. Building
Lakekeeper with its owning scripts is a separate prerequisite, not an IdP build.

| Concern | Kanidm 1.12.0 | Rauthy 0.37.2 | Keycloak 26.8.2 |
| --- | --- | --- | --- |
| Project license | MPL-2.0 | Apache-2.0 | Apache-2.0 |
| Source-build evidence | Cargo workspace MSRV 1.96; rust-toolchain says mutable `stable`; native system libraries and UI build inputs also need locks | MSRV 1.95.0; upstream builder uses Rust 1.95.0 on Debian bookworm, Node 22, C/C++/Clang; some build helpers are unpinned | Maven/Java build; upstream container already uses UBI 9 micro and Java 21, but copies a prebuilt distribution |
| Dependency-size method | 804 Cargo.lock package entries | 762 Cargo.lock package entries | 484 `.jar` regular files in each native upstream image filesystem |
| What a hardened UBI 9 effort still needs | Pin Rust and all RPM/native/UI inputs; build from source natively on both CPUs; preserve MPL obligations and qualify reproducibility | Pin Rust, native/Node/UI/wasm inputs; build on UBI 9 rather than assume Debian binary ABI compatibility; qualify both CPUs | Pin JDK/Maven/frontend dependencies/RPMs and distribution build; upstream UBI base alone is not source-build/reproducibility proof |

Counts include workspace packages and multiple versions of a crate; they are not
unique runtime dependencies or comparable units to jars. Registry/git-only and
unique-name counts are retained in [source-survey.json](idp-evidence/source-survey.json).
Licenses are project declarations, not a transitive license review.
Sources: Kanidm [Cargo.toml](https://github.com/kanidm/kanidm/blob/v1.12.0/Cargo.toml),
[toolchain](https://github.com/kanidm/kanidm/blob/v1.12.0/rust-toolchain.toml);
Rauthy [Cargo.toml](https://github.com/sebadob/rauthy/blob/v0.37.2/Cargo.toml),
[builder](https://github.com/sebadob/rauthy/blob/v0.37.2/Dockerfile_builder);
Keycloak [container](https://github.com/keycloak/keycloak/blob/26.8.2/quarkus/container/Dockerfile),
[license](https://github.com/keycloak/keycloak/blob/26.8.2/LICENSE.txt).

### Upstream-image vulnerability scans

Trivy **0.76.2** and Grype **0.121.3** binaries are SHA-256 pinned for each native
architecture. Counts are unique target/package/installed-version/advisory findings
at High or Critical severity with a known fix. They are not counts of unique CVEs
across the image. Scanner failure is an error, never a zero. Findings do not gate
this evaluation; scanner execution failures do. Full JSON includes database dates,
package evidence and scanner-specific matching. No suppression or fix was applied.

Final [actual scan run](https://github.com/datopsis/lakehouse-integration/actions/runs/43378071591), completed on both architectures:

| IdP | Trivy amd64 H/C | Trivy arm64 H/C | Grype amd64 H/C | Grype arm64 H/C |
| --- | --- | --- | --- | --- |
| Kanidm | 0 / 0 | 0 / 0 | 0 / 0 | 0 / 0 |
| Rauthy | 1 / 0 | 1 / 0 | 4 / 1 | 4 / 1 |
| Keycloak | 1 / 0 | 1 / 0 | 1 / 0 | 1 / 0 |

Trivy DB timestamp: 2026-11-13 00:58 UTC; Grype DB built: 2026-11-12 06:20 UTC.
Rauthy's Grype findings are in Debian `libssl3` 3.0.20; Keycloak's High finding
is Guava 33.6.0-jre (`GHSA-xxph-c9ww-hj94`, fixed in 33.7.2).
Different severities/matching feeds explain why scanners need separate columns;
findings have not been exploitability-triaged. A zero image scan does not prove
absence of vulnerabilities in statically linked Rust dependencies or application
protocol logic. No vulnerability gate in an owning repository is changed.

### Release cadence, maintainers and security response

Window: **2025-11-13 through 2026-11-13 UTC**. Stable GitHub releases exclude
prereleases and drafts, but include maintenance branches. Median gaps use adjacent
publication dates. Main/default-branch commits in the same window establish
activity, not access permissions or maintenance responsibilities.

| Evidence | Kanidm | Rauthy | Keycloak |
| --- | --- | --- | --- |
| Stable releases | 21 | 18 | 24 |
| Median gap | 8.39 days | 11.87 days | 13.56 days |
| Active maintainers substantiated | At least 2: Firstyear, yaleman | At least 1: sebadob | 11 of 11 in active-maintainer roster |
| Identified commit authors, including bots | 45 | 55 | 336 |
| Public advisories published in window | 10 | 6 | 20 |
| All public advisories returned | 10 | 6 | 83 |

Kanidm names two core security contacts and assigns Python ownership to yaleman;
Rauthy identifies its owner/security contact; neither supplies an exhaustive
active-maintainer roster comparable to Keycloak's. The two lower bounds must not
be read as exhaustive counts. Keycloak's eleven listed maintainers all have commit
activity in this window. Sources and counts are retained in
[source-survey.json](idp-evidence/source-survey.json), with exact surveyed commits,
release URLs, advisory URLs, publication/update dates and affected/fixed versions.

Kanidm's [security policy](https://github.com/kanidm/kanidm/blob/v1.12.0/SECURITY.md)
requests coordinated disclosure with a 60-day grace period. Its history includes
OAuth trust subject-validation, LDAP/SCIM parser denial of service, and an arbitrary
write issue with published patched release ranges
([GHSA-xxwr-vvr3-2g9f](https://github.com/kanidm/kanidm/security/advisories/GHSA-xxwr-vvr3-2g9f)).
Rauthy's [policy](https://github.com/sebadob/rauthy/blob/v0.37.2/SECURITY.md) has no
LTS or security backports while pre-1.0; consumers track current patches. Its
[authorization-code redirect binding advisory](https://github.com/sebadob/rauthy/security/advisories/GHSA-55g7-fq48-7mr4)
and [open redirect advisory](https://github.com/sebadob/rauthy/security/advisories/GHSA-3655-qc66-8pmp)
list 0.37.0 as fixed; refresh-token cross-client minting lists 0.36.1. The newer
DPoP advisory's structured patched-version field is empty, so this survey does not
invent a patch version from its publication date.
Keycloak's [security policy](https://github.com/keycloak/keycloak/blob/26.8.2/SECURITY.md)
and advisories show ongoing coordinated fixes, including
[replay protection](https://github.com/keycloak/keycloak/security/advisories/GHSA-xpwp-2pcm-8xq3)
fixed in 26.7.4. Advisory totals reflect disclosure practice and project age, not
comparative defect rates. Initial private report/acknowledgement dates are not
uniformly public: **response-time SLA/median is unverified for all three**.
No vulnerability reports were sent upstream.

## Recommendation and remaining verification

**Recommendation: prefer Rauthy for the Phase B Rust implementation; retain
Keycloak as the control and fallback. None passes the requested native-grant
requirement across all three engines because Sail lacks that client capability.**
Rauthy supplies the conventional signed
client-credentials token and human access-token groups this design needs, supports
native bootstrap JSON, and has a substantially smaller measured footprint than
Keycloak. The tradeoffs are its pre-1.0/no-backport policy, concentrated maintenance
and upstream image findings. These require an explicit ownership/patching plan in
any later hardened-image effort.

Keycloak has the strongest substantiated maintainer breadth and mature production
deployment options, with the same successful independent OAuth flows and claims.
Its larger resource and Java dependency footprint are costs, not disqualifiers.
Prefer it if operational maturity outweighs the Rust preference. Kanidm is the
least direct fit here: the client-credentials JWE and groups confined to ID tokens
in this fixture introduce client and authorization-layer work that is absent from
the other two configurations. Its successful PKCE and service-account exchange
still make it viable for different requirements. All three pass the exercised
Lakekeeper signed-token checks; Kanidm's JWE incompatibility is separate from
those signed-token security results.

The approved Phase A proxy is exercised here. The remaining common blocker is
Sail's lack of native OAuth grant/token-lifecycle support. Choose an explicit
supported integration or upstream change before treating all three engines as
qualified; passing a harness-acquired token does not remove that requirement.
The owner's choice is recorded in the Decision section above. This PR changes no
production or main-integration authentication setting.

Not tested: production database profiles; backup restoration and encryption-key
recovery; multi-node HA, partitions or failover; load, long-lived refresh and
logout/revocation; a comparative MFA/passkey evaluation (Kanidm TOTP enrollment
and login are exercised); production secret-management/drift reconciliation;
UBI 9 IdP source builds with pinned toolchains; transitive license review; full
Rust source/SBOM vulnerability coverage; Phase C authorization and STS/table
isolation. The evaluation qualifies the IdP and catalog token transport only,
not every Phase A storage/query transport. Tokens and private keys are never
published as evidence.
