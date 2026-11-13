# Identity provider bake-off (Phase B)

Survey date: 2026-11-13. **Evaluation only; no IdP is qualified for the lakehouse.**
The separate [workflow](../.github/workflows/idp-bakeoff.yml) runs manually and on
relevant pull requests, on native `ubuntu-24.04` and `ubuntu-24.04-arm`. Both run
the same assertions. It is not a dependency of the required `Integration` check.
The Integration workflow, login setting, image locks and source pins are unchanged.

## Shared prerequisite blocker

The pinned Lakekeeper **0.13.4**, image-source revision
`2200c516919a9667e9761a6581b848de32b693d1`, implements a
[plain TCP listener](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/serve.rs).
[TLS-PLAN.md](TLS-PLAN.md) explicitly leaves even a loopback plaintext proxy
exception undecided. This evaluation follows the instruction that tokens never
travel in plaintext. No bearer token is sent to that listener and no plaintext
proxy backend is introduced.

Each IdP gets a disposable Lakekeeper configuration with OpenID enabled,
`OPENID_AUDIENCE=lakekeeper`, `OPENID_SUBJECT_CLAIM=sub`, and
`OPENID_ROLES_CLAIM=groups`. The existing repository build scripts and strict
provenance/binary checks build Lakekeeper and PostgreSQL without changing pins.
The preflight requires Lakekeeper to become healthy, requires **401** from an
anonymous request, then attempts verified TLS without sending any token. This
separates a working authentication-enabled plaintext service from an unrelated
startup failure. Keycloak receives exactly the same preflight as both candidates.

Consequently the following remain **BLOCKED, not passed or candidate failures**:
Trino 484, PyIceberg 0.12.0 and Sail 0.7.3 obtaining a token **and listing/reading a
table through Lakekeeper**; human-token acceptance; valid-token acceptance;
wrong-audience, expired, different-key and unsigned/alg=none rejection; and
Lakekeeper's acceptance of new tokens after signing-key rotation. No simulated
catalog or local JWT verifier is substituted for Lakekeeper. Those assertions
are absent from the executable harness beyond their blocked evidence entries;
this PR is not a completed end-to-end qualification suite.

The workflow fails qualification while any such entry is blocked. An IdP-only
pass means only the named subtest passed. The existing Integration check can be
green while this separate evaluation is red.

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
Keycloak's single-node fixture uses Narayana's upstream
[MBeanProcessId](https://github.com/jbosstm/narayana/blob/7.3.4.Final/ArjunaCore/arjuna/classes/com/arjuna/ats/internal/arjuna/utils/MBeanProcessId.java)
through `JAVA_OPTS_APPEND`, replacing the default socket-based process identifier.
This avoids its otherwise-unnecessary plaintext loopback reservation; it does not
disable transactions or recovery. Listener enumeration must match the configured
TLS ports exactly, excluding Docker's internal DNS stub. Each application port
must accept the generated CA/hostname and reject unknown CAs, wrong hostnames and
anonymous plaintext requests. A TLS fatal decode-error alert is a rejection.

## Runtime comparison

Results and run links will be populated from the final native artifacts. Early
run [43368663460](https://github.com/datopsis/lakehouse-integration/actions/runs/43368663460)
found a common harness env-file ownership bug before IdP startup; that is not
candidate evidence. Its complete scans are valid independent evidence.

## Grant and authorization-layer implications

Kanidm 1.12.0 **does implement client_credentials**. Its
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
| Dependency-size method | 804 Cargo.lock package entries | 762 Cargo.lock package entries | Count every `.jar` regular file in the upstream image filesystem, per architecture; runtime evidence below |
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

Initial [actual scan run](https://github.com/datopsis/lakehouse-integration/actions/runs/43368663460):

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

Pending final native runtime evidence. No production selection or security
qualification is justified by the source survey or image scans alone.

Not tested: all Lakekeeper token-acceptance/rejection and table-read assertions
listed above; Trino/Sail runtime token acquisition; production database profiles;
backup restoration and encryption-key recovery; multi-node HA, partitions or
failover; load, long-lived refresh and logout/revocation; MFA/passkeys; production
secret-management/drift reconciliation; UBI 9 IdP source builds; transitive license
review; full Rust source/SBOM vulnerability coverage; Phase C authorization and
STS/table isolation. Tokens and private keys are never published as evidence.
