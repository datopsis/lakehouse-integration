# Identity provider bake-off (Phase B)

Survey date: 2026-11-13. **Evaluation only; no IdP is qualified for the lakehouse.**
The separate [workflow](../.github/workflows/idp-bakeoff.yml) runs manually and on
relevant pull requests, on native `ubuntu-24.04` and `ubuntu-24.04-arm`. Both run
the same assertions. It is not a dependency of the required `Integration` check.
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

The runtime table below is the **historical pre-approval run** until replacement
native Actions evidence has been inspected. Its plaintext-listener blockers no
longer describe the approved test design.

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

Final native [run 43372083311](https://github.com/datopsis/lakehouse-integration/actions/runs/43372083311), harness revision
`e28aa4a57596b8ded5640730020ea3a0ad456eff`. **PASS** is scoped to the named
assertion; **BLOCKED** is not a pass or an IdP-specific failure. The JWT-format
row decodes and checks fields against discovery/JWKS; it does not establish
signature validation by Lakekeeper. **N/T** means not tested.

| Assertion | Kanidm amd64 | Kanidm arm64 | Rauthy amd64 | Rauthy arm64 | Keycloak amd64 | Keycloak arm64 |
| --- | --- | --- | --- | --- | --- | --- |
| Startup, provisioning and discovery | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Verified TLS; CA/hostname/plaintext negatives; exact listeners | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Client-credentials token endpoint (HTTP 200) | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Machine signed-JWT format/iss/aud/sub/exp/JWKS kid | [FAIL][amd64] | [FAIL][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| PyIceberg token acquisition only | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Human code + S256 PKCE at IdP only | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Groups in human access token | [FAIL][amd64] | [FAIL][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Groups in human ID token | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Service-account RFC 8693 exchange, custom harness | [PASS][amd64] | [PASS][arm64] | [N/T][amd64] | [N/T][arm64] | [N/T][amd64] | [N/T][arm64] |
| New signing key and new-token kid published | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Startup/RSS/storage measurement | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] | [PASS][amd64] | [PASS][arm64] |
| Lakekeeper verified-TLS prerequisite | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| Trino 484 grant + list/read | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| PyIceberg grant + list/read | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| Sail 0.7.3 grant + list/read | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| Human token accepted by Lakekeeper | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| Valid token accepted by Lakekeeper | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| Wrong audience rejected by Lakekeeper | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| Expired token rejected by Lakekeeper | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| Different signing key rejected by Lakekeeper | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| Unsigned/alg=none rejected by Lakekeeper | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |
| New token accepted after IdP rotation by Lakekeeper | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] | [BLOCKED][amd64] | [BLOCKED][arm64] |

[amd64]: https://github.com/datopsis/lakehouse-integration/actions/runs/43372083311/job/131709936602
[arm64]: https://github.com/datopsis/lakehouse-integration/actions/runs/43372083311/job/131709936992

Durable sanitized summaries, decoded claims, public JWKS, exact errors, source
build/provenance results, scan versions/counts and full-artifact SHA-256 manifests:
[amd64](idp-evidence/amd64.json), [arm64](idp-evidence/arm64.json).
The run's `idp-bakeoff-amd64-43372083311-1` and `idp-bakeoff-arm64-43372083311-1`
artifacts retain the complete scanner JSON and sanitized service logs for 14 days.
The committed summaries remain after those artifacts expire.

Both architectures report the same Kanidm machine-format error:
`Expected signed JWT (3 segments), received 5-segment token (JWE is not a Lakekeeper JWT)`.
Its access-token groups assertion fails because the `groups` field is absent;
the ID token does contain group UUIDs and names. The configured Lakekeeper reports
anonymous HTTP **401** and TLS **`[SSL: WRONG_VERSION_NUMBER]`** for every provider
on both CPUs. No token is sent during this transport preflight.

Earlier runs exposed fixture errors, not candidate failures: env-file ownership
([43368663460](https://github.com/datopsis/lakehouse-integration/actions/runs/43368663460));
empty scope, issuer normalization and Kanidm MFA provisioning
([43369108418](https://github.com/datopsis/lakehouse-integration/actions/runs/43369108418));
TLS-alert classification, Keycloak's socket process identifier and missing `basic`
scope ([43369788776](https://github.com/datopsis/lakehouse-integration/actions/runs/43369788776)).
The stricter subject assertion also identified Rauthy's default omission of `sub`
([43371308288](https://github.com/datopsis/lakehouse-integration/actions/runs/43371308288));
the final fixture enables its upstream subject mapping setting.
The intermediate diagnostic run was superseded/cancelled. Only the final run above
supports the table; both architectures use identical assertions.

### Decoded claims

These are selected fields from the final amd64 synthetic human login. Full decoded
access/ID claims for **both** architectures are in the summaries above. ID-token
groups are not silently substituted for API access-token groups.

Kanidm access token:

```json
{
  "iss": "https://kanidm.idp.test:8443/oauth2/openid/lakekeeper",
  "aud": "lakekeeper",
  "sub": "e0edfd9a-da9d-4e9e-8240-8d1b1f7edb44",
  "exp": 1794548687,
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
    "629fafcd-1e6b-431f-8139-63d5ad984201",
    "lake-readers@kanidm.idp.test"
  ]
}
```

Rauthy access token:

```json
{
  "iss": "https://rauthy.idp.test:8443/auth/v1/",
  "aud": "lakekeeper",
  "sub": "IMifmK5NCMYbku47FgAk7Xjz",
  "exp": 1794547890,
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
  "sub": "3ade7490-fc9e-4ce9-94c6-50af7e0b8944",
  "exp": 1794548045,
  "scope": "openid email profile",
  "groups": [
    "lake-readers"
  ]
}
```

## Grant and authorization-layer implications

Kanidm 1.12.0 **does implement client_credentials**, but its JWE is not a JWT that
the pinned Lakekeeper JWKS authenticator can validate. There is no JWE decryption
or Kanidm introspection configured in that authentication path. The direct
Lakekeeper request records the real HTTP result rather than relying on segment
count alone. Kanidm 1.12.0 **cannot emit group claims in access tokens** through
its supported claim mappings: extra/group claims are placed in ID tokens and
userinfo; its RFC 9068 access-token structure has no group/custom-claim field.
The source and decoded access/ID tokens establish this version-specific limitation.

Its
[implementation](https://github.com/kanidm/kanidm/blob/v1.12.0/server/lib/src/idm/oauth2.rs)
encrypts a `ClientAccess` structure into JWE on that grant. Its separate
[service-account RFC 8693 exchange](https://github.com/kanidm/kanidm/blob/v1.12.0/book/src/accounts/service_accounts.md)
uses an API token as the subject token, without the OAuth client secret. An
exchange performed by this test harness is not evidence that a stock engine
performs it. Runtime token format and exchange results are reported separately.

The pinned [Sail credential implementations](https://github.com/lakehq/sail/blob/ac4690078021cf2a5402dc5c7b38a886f1916c73/crates/sail-catalog/src/credentials.rs)
are empty, static bearer and file bearer providers. That source inspection does
not establish native OAuth client-credentials or RFC 8693 support. Feeding an
externally acquired token into a file would require another token-lifecycle
component and does not satisfy the requested stock-client grant test.
PyIceberg's existing legacy OAuth manager is exercised separately for token
acquisition; this is explicitly not a table-read pass.

Kanidm's direct exchange succeeds in the custom HTTP harness, but **stock-client
exchange compatibility is not established**. In particular, this Sail revision
has no built-in grant/exchange provider in the inspected implementation. Trino's
exchange configuration was not exercised. Do not describe the direct RFC 8693
request as a solution that works across all three engines without custom code.

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
| Kanidm | [amd64][amd64] | 1.192 | 66.1 | 2.98 | 261.3 |
| Kanidm | [arm64][arm64] | 1.150 | 74.2 | 2.98 | 268.6 |
| Rauthy | [amd64][amd64] | 15.164 | 73.9 | 6.34 | 90.6 |
| Rauthy | [arm64][arm64] | 8.143 | 74.4 | 6.34 | 93.2 |
| Keycloak | [amd64][amd64] | 31.438 | 590.9 | 2.31 | 451.4 |
| Keycloak | [arm64][arm64] | 27.433 | 574.7 | 2.25 | 452.6 |

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

Final [actual scan run](https://github.com/datopsis/lakehouse-integration/actions/runs/43372083311), completed on both architectures:

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

**Provisional recommendation: carry Rauthy into the next Rust-focused qualification
stage; retain Keycloak as the control and fallback. Do not select a production IdP
from this incomplete qualification.** Rauthy supplies the conventional signed
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
still make it viable for different requirements.

The next prerequisite is a separately reviewed, fully encrypted Lakekeeper serving
path consistent with Phase A. Then implement and run every blocked engine/security
assertion against the real catalog, including explicit Sail grant support. No
provider gets credit for rejecting forged tokens merely because its own token
endpoint works. The owner remains responsible for the IdP choice; this PR changes
no production or main-integration authentication setting.

Not tested: all Lakekeeper token-acceptance/rejection and table-read assertions
listed above; Trino/Sail runtime token acquisition; production database profiles;
backup restoration and encryption-key recovery; multi-node HA, partitions or
failover; load, long-lived refresh and logout/revocation; a comparative MFA/passkey
evaluation (Kanidm TOTP enrollment/login is exercised to satisfy its policy); production
secret-management/drift reconciliation; UBI 9 IdP source builds; transitive license
review; full Rust source/SBOM vulnerability coverage; Phase C authorization and
STS/table isolation. Tokens and private keys are never published as evidence.
