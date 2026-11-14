# Decision record

Owner decisions for the Datopsis lakehouse and its image repos, newest first, followed by the decisions still pending.

Each entry records **what** was decided, **why**, and **where** it is implemented. A decision changes only by a new dated entry that supersedes the old one; old entries are never deleted.

Items still under coordinated vulnerability disclosure are tracked privately and appear here only in general terms.

## Decided

| Date | Area | Decision | Why | Where |
|---|---|---|---|---|
| 2026-11-14 | Docs | Every feature that changes the architecture updates `docs/diagrams/*.svg` in the same PR or an immediate docs follow-up. | Diagrams are the shared map; stale diagrams mislead. | All repos and child briefs |
| 2026-11-13 | Authorization (C) | **OpenFGA as the interim backend.** Plan an own authorization platform built on the open-source Cedar Rust library. R1–R11 are complete for now; future capabilities are catalogued. | Open-source Lakekeeper supports only OpenFGA, which ignores token groups. Built-in Cedar is in the paid Lakekeeper Plus. No option covers catalog, engines, Sail and storage together. | [AUTHZ-PLATFORM-PLAN.md](AUTHZ-PLATFORM-PLAN.md) |
| 2026-11-13 | Identity (B) | **Rauthy** is the OpenID provider; **Keycloak** is the tested fallback. Kanidm is rejected. | Rauthy and Keycloak pass every Lakekeeper token test on both architectures; Rauthy uses about 75 MiB vs 570 MiB, and is Rust and Apache-2.0. Kanidm's machine tokens are encrypted (Lakekeeper returns 401), and it puts no groups in access tokens. | [IDP-BAKEOFF.md](IDP-BAKEOFF.md), `rauthy-ubi` |
| 2026-11-13 | Sail TLS | Document the slow-reader stream reset at about 80 s behind the proxy. A narrow PySpark retry/reattach policy is a blocking check, with an exact-outcome canary for the raw reset. An upstream request to make keepalive configurable is drafted, not filed. | Sail 0.7.3 hard-codes HTTP/2 keepalive (60 s + 10 s); no proxy setting fixes it; the client policy recovers every row. | `sail-ubi` (e96e068) |
| 2026-11-13 | Trino TLS | Merge the Trino TLS work into the Iceberg draft branch, so the integration test can pin one commit. Main is untouched. | The integration test pins the draft until upstream jar fixes land. | `trino-ubi` draft #2 at 685ff5b |
| 2026-11-13 | SeaweedFS CVEs | Wait for a SeaweedFS release that fixes the new Go-module findings, and **keep using 4.53** meanwhile. The seaweedfs-ubi gate stays red and blocking; downstream keeps its 4.53 pins and may pin an unmerged seaweedfs-ubi PR commit. | No module bumps, patches or exemptions. | `seaweedfs-ubi` #82 |
| 2026-11-12/13 | SeaweedFS internal TLS | Identity tests stay strict, and failures block. For the integration test, an interim narrowest-working trust setting is an accepted, documented residual risk, guarded by exact-outcome canaries until upstream fixes land. | Upstream limitations; details under coordinated disclosure. | `seaweedfs-ubi` |
| 2026-11-12 | TLS (A) | 1) Plain text is allowed **only** over 127.0.0.1 or a Unix socket inside one network namespace (proxy to Lakekeeper or Sail; local PostgreSQL socket). 2) The proxy is **nginx-ubi**. 3) Strict SeaweedFS identity tests. 4) Phase A covers encryption and server identity only; user authentication is Phase B. | Lakekeeper and Sail can't serve TLS; tokens and vended keys must never travel in plain text. | [TLS-PLAN.md](TLS-PLAN.md), diagrams |
| 2026-11-12 | Vulnerability gate | "Fixable" means the fixed RPM is **installable from the UBI repos the image builds from**. Unavailable fixes are reported, tracked in one issue, and block automatically once published. Query errors and non-RPM findings always block. No CVE lists. | Vendor fixes can appear before UBI publishes them, which blocked everything with no action possible. | All image repos |
| 2026-11-12 | ClickHouse backup | Native BACKUP/RESTORE to S3: daily at 02:00 UTC, a weekly full, 30-day retention, an alert after 26 h without success. CA trust is scoped to the cluster CA plus pinned Amazon roots. **Object Lock is off by default** and documented, so users enable Governance mode themselves. | Ransomware protection is the user's choice; trusting every public CA was too broad. | `clickhouse-production-stack` |
| 2026-11-11 | Security order | Security first, in order: **A** TLS, **B** OpenID login, **C** authorization, **D** catalog-controlled data access. | Catalog permissions protect nothing while engines hold bucket-wide keys. | [ROADMAP.md](ROADMAP.md) |
| 2026-11-11 | Data access (D) | Use **credential vending through SeaweedFS STS**. Remote signing is not safe on SeaweedFS; it stays a documented feature with prominent warnings. SeaweedFS IAM/STS may become supported subject to adversarial tests. | Signed requests can be altered on SeaweedFS; STS session policies scope access to the table. | `seaweedfs-ubi`, [ARCHITECTURE.md](ARCHITECTURE.md) |
| 2026-11-11 | Static keys | Engines keep static S3 credentials on the main path until Phase D. | Sail 0.7.3 falls back to static keys; vending isn't qualified yet. | Integration test |
| 2026-11-11 | Architectures | Run the full integration test natively on **amd64 and arm64**, with identical assertions and no emulation. Supersedes amd64-only (2026-11-10). | Owner authorized arm64. | CI (`Integration`) |
| 2026-11-11 | Repo hygiene | LF line endings everywhere (`.gitattributes`, a pre-commit hook, a CI check). A "Protect main" ruleset requires a PR and green, up-to-date checks. | CRLF broke builds; main must stay releasable. | All repos |
| 2026-11-10 | Integration test | A separate repo; images built from pinned commits with strict provenance. A Lakekeeper-specific PostgreSQL image with five extensions. Trino first, then Sail. Lakekeeper login off in v1, documented as a gap. | Prove the images work together; keep `postgresql-ubi` extension-free. | This repo |
| 2026-11-10 | Trino jars | Iceberg draft PR #2 waits for upstream Guava and Jackson fixes: **no exemptions, no patched jars**. | The vulnerability gate stays meaningful. | `trino-ubi` #2 |
| 2026-11-10 | Parquet | Set `parquet.writer.delta-length-byte-array-encoding-enabled=false`, with a canary that flags the upstream fix. | Works around an Arrow decoder bug. | Trino config, canary |
| 2026-11-09 | ClickHouse stack | v1: Ansible provisions AWS VMs, then Podman/Compose deploys the services; Kubernetes later. Agents never touch a real AWS account. | Owner design. | `clickhouse-production-stack` |
| 2026-11-09 | Hardening standard | `container-hardening` is a reference only, not a CI gate. A fixable finding in an upstream bundle is cleared only by removing the unused component, never by an exemption. | Each image repo owns its own gate and release. | All image repos |

## Pending decisions

Ordered roughly by when they block work. The owner answers them one at a time.

| # | Decision | Options or notes | Blocks |
|---|---|---|---|
| 1 | Authorization platform: policy engine | Cedar library (recommended) or another | Phase C build |
| 2 | Authorization platform: name and repo layout | One repo per component (recommended) or a monorepo | Phase C build |
| 3 | Interim OpenFGA depth | Evaluation only (recommended) or a hardened `openfga-ubi` | Phase C interim |
| 4 | Authorization order | Spikes S1–S4 first (recommended) or straight to the MVP | Phase C build |
| 5 | License for new code | Apache-2.0 suggested | New repos |
| 6 | Future authorization capabilities | Which of the 27 catalogued options come after the MVP; suggested first bundle: governance basics | Post-MVP roadmap |
| 7 | Upstream filings (drafted, unfiled) | Sail keepalive request; PyIceberg/fsspec remote-signing race; an Iceberg 1.12.x Guava backport request | Faster upstream fixes |
| 8 | PostgreSQL local socket | Replace `local all all trust` with peer or password auth | Hardening |
| 9 | Phase D switch-over | When to enable vending on the main path and remove engines' static keys | Phase D |
| 10 | ClickHouse backup operations | Database scope, alert ownership | Production use |
| 11 | Drift-notification rollout | Confirm the nginx-ubi pilot notification arrived, then copy it to the other repos | Update awareness |
| 12 | `container-hardening` #25 | Two applicability decisions | That PR |

## Waiting on upstream (no decision needed; recheck)

| Item | Waiting for | Next check |
|---|---|---|
| Trino Iceberg connector (#2) | An Iceberg release with Guava 33.7.2+ (no 1.12.x backport yet) and a Trino release carrying it; Parquet 1.18.2 is already on Trino master | When Trino 485 ships, or in about 2 weeks |
| SeaweedFS Go modules | A SeaweedFS release with `golang.org/x/net` 0.62+ and `apache/thrift` 0.25+ | On each SeaweedFS release |
| Parquet encoding workaround | Arrow decoder fix (the canary reports it) | Automatic |
| Remote-signing canary (T9) | PyIceberg/fsspec race fix (the canary reports it) | Automatic |
