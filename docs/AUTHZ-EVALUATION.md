# Authorization backend evaluation (Phase C)

**Provisional recommendation: OpenFGA for this pinned open-source Lakekeeper.**
Cedar is open source, but is not a drop-in backend for this binary. Neither choice
is qualified by this preparation alone. Runtime results are being collected.
Rauthy remains the selected OpenID provider; Keycloak is the Phase B fallback.
Amazon Verified Permissions, a hosted service, is out of scope.

## What the pin actually supports

The main lock pins `lakekeeper-ubi` to
`2200c516919a9667e9761a6581b848de32b693d1`. Its
[artifact lock](https://github.com/datopsis/lakekeeper-ubi/blob/2200c516919a9667e9761a6581b848de32b693d1/artifacts/lakekeeper.lock.json)
identifies official Lakekeeper **0.13.4**, source commit
**`9bd377162345b64a716f0a4fcffe4e7e7f3c7534`**.

At that exact commit:

- The open-source binary's
  [authorizer factory](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper-bin/src/authorizer.rs)
  implements **OpenFGA and AllowAll only**. `AuthZBackend::External(String)` is an
  extension mechanism, not evidence that any named policy engine is implemented.
  The factory chooses AllowAll when OpenFGA is not selected. Do not configure
  `cedar` on this binary and assume authorization is enforced.
- The pinned [authorization documentation](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/docs/docs/authorization.md)
  labels built-in Cedar as **Lakekeeper Plus**. That integration is separate from
  the open-source Cedar language and engine.
- The pinned [configuration documentation](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/docs/docs/configuration.md#authorization)
  explicitly says the default OpenFGA implementation **does not use token roles**.
  Setting `OPENID_ROLES_CLAIM=groups` parses the claim but does not grant access.
  The [OpenFGA authorizer](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/authz-openfga/src/authorizer.rs)
  uses stored relationships; Rauthy emitting `groups` is insufficient.
- The pinned [OpenFGA guide](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/docs/docs/authorization-openfga.md)
  requires OpenFGA >=1.11 and describes namespace inheritance, explicit role
  membership, and a Trino OPA bridge. This evaluation exercises catalog checks,
  not Trino end-user impersonation or that bridge.

The [source inventory](authz-evidence/source.json) records exact file hashes,
upstream revisions, declared dependency counts, release dates, and public advisory
snapshots, surveyed 2026-11-13. These source conclusions are not runtime passes.

## Candidate comparison

| Question | OpenFGA 1.22.1 | Cedar 4.14.1 |
| --- | --- | --- |
| License / implementation | Apache-2.0 / Go | Apache-2.0 / Rust |
| Pinned Lakekeeper native backend | Yes | No; built-in Cedar is Plus |
| Rauthy `groups` directly grants access | Not consumed by this Lakekeeper authorizer | Can express groups in entities; an integration must authenticate and map claims |
| Namespace/table enforcement | Lakekeeper owns the model, hierarchy and permission checks | CLI prototype only; no catalog interception |
| Trino/PyIceberg machine identities | Both can acquire Rauthy tokens and face Lakekeeper checks | Needs a custom Trino access-control plugin or external enforcement point; PyIceberg/catalog paths need their own enforcement |
| Phase D credential scope | Lakekeeper read/write decision feeds credential generation | Standalone Cedar cannot gate Lakekeeper vending; needs a catalog integration |
| Durable state | OpenFGA database, separate from catalog DB | Library has no database; application owns policy/entity persistence |
| Integration cost | Deployment, DB, model lifecycle, role provisioning/synchronization | Principal/action/resource mapping, schema, entity resolver, policy deployment, failure behavior, cache/revocation and enforcement integration |
| Preferred use here | Phase C starting point, conditional on runtime results and group strategy | Future policy-engine option; not a replacement for this pin |

Cedar's [Apache-2.0 license](https://github.com/cedar-policy/cedar/blob/47d82a8293354f235d3f8d092c71071706401741/LICENSE)
and [library/CLI](https://github.com/cedar-policy/cedar/tree/47d82a8293354f235d3f8d092c71071706401741)
are open source. The official CLI exercises the same policy language without
inventing a Lakekeeper connector. A service/agent wrapping the library would also
need a versioned API, authenticated verified TLS (nginx-ubi where necessary),
policy/entity distribution, resource limits and fail-closed error handling.
A Trino-only plugin cannot protect clients that reach Lakekeeper directly. A
reverse proxy alone cannot infer all Iceberg actions, filter list responses or
safely scope credentials; it needs application-aware integration.

## Inputs and transport

The evaluation-only [input manifest](../evaluation/authz/inputs.json) never feeds
`images.lock.json` or `integration/build.py`.

| Component | Exact input |
| --- | --- |
| OpenFGA | Official `docker.io/openfga/openfga@sha256:b852071314f1fda1194d341a6ebac0a4f619b3cd87a6626d2ccc7048af4ec671` (1.22.1, both native platforms) |
| Cedar CLI amd64 | Official 4.14.1 `x86_64-unknown-linux-gnu` archive; SHA-256 `5833e9f4734eac0d95b3dab7ae119a9212caf0a82e02720b989e2fce6f3bfdad` |
| Cedar CLI arm64 | Official 4.14.1 `aarch64-unknown-linux-gnu` archive; SHA-256 `499cfb6a6a7eab28ceca7b24215525a2d107fbf3faca759318a253d485b7d346` |
| Rauthy | Existing bake-off 0.37.2 upstream digest `sha256:d733b7580f53c1601c286b5504853b2774e70245f5f9427d9bcda32496b753ee` |
| nginx-ubi | `9ef9e822c6b5e508cebef2adff3bb647a206773c`, native owner build and strict provenance |
| Lakekeeper / PostgreSQL / SeaweedFS / Trino | Existing unchanged repository pins and owner builds; no authorization hardening images created |

The [workflow](../.github/workflows/authz-evaluation.yml) is `workflow_dispatch`
only, with native `ubuntu-24.04` and `ubuntu-24.04-arm` runners and identical
assertions. It has read-only permissions and no dependency relationship with the
required `Integration` check. There is no QEMU or architecture-specific waiver.

The fixture generates a fresh CA and secrets on each runner. Rauthy (including
Hiqlite), OpenFGA HTTP/gRPC, PostgreSQL connections (`verify-full`), SeaweedFS HTTP
and mTLS gRPC, Trino HTTPS, and client calls use verified TLS. Lakekeeper uses the
unchanged nginx-ubi Lakekeeper profile and the already approved
`127.0.0.1:8182` plaintext hop inside the shared network namespace. This is the
only intentional plaintext TCP exception; local PostgreSQL administrative Unix
sockets do not cross the network. No listener is published to the host.

Rauthy provisioning and authorization-code/S256 PKCE login reuse the bake-off
implementation. The bootstrap operator has a separate machine subject and token
audience; Lakekeeper explicitly trusts `lakekeeper,operator`. The reader machine
uses `lakekeeper`; the human has `lake-readers` in the access token. The fixture
creates `bakeoff.sample` and `denied.sample`, each with exact rows
`[{"id":1,"label":"alpha"},{"id":2,"label":"beta"}]`.

First, a role receives `select` on `bakeoff` with **no stored user membership**.
That tests the actual token-claim requirement. An explicit OpenFGA assignee tuple
is a separately labeled workaround, never a group-claim pass. Subsequent direct
user and machine grants test positive reads, namespace denials, write denials and
revocation. A denial must be an authorization/hidden-resource result; expired
credentials, timeouts and arbitrary exceptions cannot count as successful denials.

Cedar's diagnostic uses the genuine human JWT, accepted by Lakekeeper's OIDC
verifier through `whoami`, before mapping its claims into Cedar entities. It tests
list/read allow, other-namespace/write deny, and policy removal. It does not
substitute decoded claims for signature verification, and it does not claim that
the standalone decision enforces catalog access.

Only sanitized JSON/logs are uploaded. Keys, client secrets, bearer tokens, STS
credentials, environment files and database dumps are excluded. Scanner JSON is
information-only; a scanner failure is unknown, never zero vulnerabilities.

## Native runtime evidence

Pending native execution. No authorization pass/fail result is asserted yet.
The final table will distinguish PASS, FAIL, BLOCKED and N/T (not tested), with
links to the exact native jobs. Cedar catalog/engine enforcement is N/A because
there is no integration in the pin.

## Phase D: source boundary and optional probe

The pinned [`load_table`](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/server/tables/load_table.rs)
authorizes the request before fetching storage secrets and calling
`generate_table_config`. The
[authorization result](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/server/tables.rs)
maps write permission to `ReadWriteDelete`, read permission to `Read`, and
metadata-only access to no storage permission. Thus **the authorization decision
gates credential vending and its requested scope**, not merely table visibility.

The [S3 implementation](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/crates/lakekeeper/src/service/storage/s3.rs)
constructs an inline STS policy using the table location and those storage
permissions, calls `AssumeRole`, and returns temporary keys/session token with
expiry. It caches temporary credentials. Revoking a catalog grant blocks later
catalog authorization; it does **not** invalidate credentials already issued or
data already fetched. Storage must enforce the inline policy and TTL.

The optional diagnostic uses only the pinned SeaweedFS image, an evaluation-only
IAM role and a new `phase-d` warehouse. It first probes STS, then requests actual
Lakekeeper vending, requires an own-table metadata read, denies another table's
object and a write using the read-scoped credentials, and requires denied catalog
loads to return no credentials. Failures remain visible; no image or main fixture
is changed to make it work. Main evaluation clients retain static S3 keys, so the
main read tests prove catalog enforcement, **not storage isolation**.

## Operations and supply chain

| Area | OpenFGA | Cedar library / application-owned agent |
| --- | --- | --- |
| Storage | PostgreSQL supported; fixture uses a dedicated DB/user. Production should isolate capacity from catalog DB. | No intrinsic DB; persist policy/schema/entity sources and versions in the integrating application. |
| HA | Multiple service replicas with shared durable DB; database HA and cache consistency still need qualification. | Embedded engine follows host availability; an agent needs replicas and consistent policy/entity versions. |
| Backup/restore | Restore both catalog and authorization state consistently. Fixture probes SQL dump/restore and tuple count only. | Back up policy/schema, entity source and application configuration; restoring just a policy file may lose memberships. |
| Configuration as code | Pin Lakekeeper-managed model version, review tuple/grant provisioning and reconciliation. | Versioned Cedar policy/schema/entity fixtures; validate before atomic deployment and preserve rollback versions. |
| Revocation | Measure delete acknowledgement to first denied fresh REST load; cache/load/replica effects are separate. | Local policy removal visible on next CLI process; no distributed-cache or engine integration claim. |
| Memory/startup | Collected from native containers; no capacity recommendation inferred from a tiny fixture. | CLI invocation time/binary size only; not steady-state agent or embedded-library RSS. |
| Dependency inventory | 152 `go.mod` required module entries at `44054f542f64e9b9589dd26a595081b3d2cfd942`. | 389 packages in workspace `Cargo.lock` at `47d82a8293354f235d3f8d092c71071706401741`. |
| Upstream scanners | Pinned Trivy 0.76.2 and Grype 0.121.3 scan the exact upstream image on each CPU. | No official image used: image scan counts N/A. The CLI/library dependency graph still needs build-specific SBOM/scanning. |

Dependency counts describe source declarations, including transitive/build/test
packages; they are not a shipped-binary SBOM or an apples-to-apples size measure.
OpenFGA's [production guidance](https://openfga.dev/docs/best-practices/running-in-production)
recommends authenticated TLS, tuned pools and cache-aware deployment. Lakekeeper's
[pinned reconcile guide](https://github.com/lakekeeper/lakekeeper/blob/9bd377162345b64a716f0a4fcffe4e7e7f3c7534/docs/docs/authorization-openfga.md#reconciling-openfga-against-the-catalog)
says hierarchy can be reconstructed but grants, ownership and role assignments
cannot. A catalog-only backup is insufficient.

OpenFGA's [maintainer roster](https://github.com/openfga/community/blob/main/MAINTAINERS.md)
is predominantly Okta, with Grafana Labs, Netlight and independent representation.
Its recent releases are 1.19.0 (Aug 25), 1.20.0 (Sep 8), 1.21.0 (Sep 20), 1.22.0
(Oct 6) and 1.22.1 (Oct 28), 2026: active development, not a promised SLA.
Cedar is maintained in the [cedar-policy organization](https://github.com/cedar-policy/cedar)
with public contribution/security processes; releases 4.14.0 (Oct 17) and 4.14.1
(Nov 2) show continuing library and CLI maintenance. Neither is a commercial
support commitment. See the retained release/API inventory for exact dates.

Both have security history. OpenFGA's
[GHSA-h7w8-xr72-cv4r](https://github.com/openfga/openfga/security/advisories/GHSA-h7w8-xr72-cv4r)
(API policy enforcement, fixed in 1.20.0) and
[GHSA-5278-rrxc-mgf7](https://github.com/openfga/openfga/security/advisories/GHSA-5278-rrxc-mgf7)
(policy enforcement, fixed in 1.19.0) are examples covered by this version.
Cedar's [GHSA-m84h-6f26-p3p7](https://github.com/cedar-policy/cedar/security/advisories/GHSA-m84h-6f26-p3p7)
(parser memory exhaustion, fixed >=4.13) and
[GHSA-c33x-vcv4-vg3g](https://github.com/cedar-policy/cedar/security/advisories/GHSA-c33x-vcv4-vg3g)
(template validation/panic/decision divergence, fixed 4.11.1 on the 4.x branch)
are covered by 4.14.1. This is not a claim that either artifact is vulnerability-free.

A future OpenFGA UBI 9 image should acquire verified native upstream binaries or
build pinned Go source/toolchain/dependencies offline, carry the exact source and
artifact-lock labels, use a digest-pinned UBI 9 runtime with only necessary CA/time
and shared-library inputs, and run non-root with a read-only filesystem and
service-specific secrets. Keep migrations a separate job and authenticate both
HTTP and gRPC. Produce SBOMs, verify binary identity/architecture, scan OS and Go
packages, and exercise TLS, model migrations and backup recovery on both CPUs.

For Cedar, prefer embedding a locked `cedar-policy` dependency in the actual
integration. If an agent is chosen, build that wrapper and Cedar together with a
pinned Rust toolchain and vendored checksummed crates; package only the native
binary and verified runtime dependencies on UBI 9. Include the wrapper, policy
schema and entity-source contract in the SBOM/provenance boundary. The CLI is an
evaluation tool, not a production access-control service. No hardened candidate
image is built in this PR.

## Recommendation and remaining work

Choose **OpenFGA as the implementation direction**, because it is the native
open-source backend of the pin, understands Lakekeeper's hierarchy and grants,
and feeds the same decision into credential scope. Keep Rauthy and its Keycloak
fallback. **Do not declare the requested token-group requirement satisfied**:
it requires explicit membership provisioning/synchronization or a reviewed
Lakekeeper authorizer change that supplies contextual group relationships. Such
a change is outside this evaluation and must address removal/revocation too.

Keep Cedar as a future alternative when policy-as-code requirements justify an
application integration or a separately evaluated Lakekeeper Plus deployment.
A custom Trino plugin alone leaves direct catalog clients and vending uncovered.

Not qualified here: production HA/failover, load, cache staleness across replicas,
restored-service decisions, consistent cross-database recovery, policy upgrades,
Trino end-user identity propagation, Cedar catalog/plugin enforcement, issued STS
credential revocation/expiry, full source/binary supply-chain attestation or a
hardened image. Runtime/scanner results below must be read independently of this
source-based recommendation.
