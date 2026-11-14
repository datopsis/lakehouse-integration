# Plan: a Datopsis authorization platform (Phase C, and the D–C glue)

Status: **draft for owner review**, 2026-11-13. Interim decision: OpenFGA "for now".
Working name: `datopsis-authz` (placeholder).

## 1. Why build something

No single available option meets all our requirements:

| Need | OpenFGA (Lakekeeper OSS) | Lakekeeper Plus (Cedar) | Gap we keep hitting |
|---|---|---|---|
| Use Rauthy's `groups` claim directly | No; Lakekeeper's OpenFGA ignores token groups, so memberships must be synced | Unknown; commercial | Group sync |
| One policy for catalog, Trino, Sail and storage | Catalog only (+ an OPA bridge for Trino) | Catalog only | Engines enforce separately |
| Sail (Spark Connect) authentication and authorization | None; Sail runs `allow_unauthenticated_remote` | None | No enforcement point at all |
| Sail obtains its own tokens | No native grant (bake-off) | Same | Token broker needed |
| Per-table storage credentials (Phase D) | Lakekeeper vends; decisions gate it | Same | Must not regress to static keys |
| Policy as reviewed, tested code | Model + tuples (data, not code) | Cedar policies | Policy CI, analysis |
| Audit of every decision | Partial | Unknown | Unified audit |
| Rust, hardened UBI, our gates | Go | Closed | Supply chain |

## 2. Position: build the integration layer, not a policy engine

Writing a new policy language or evaluator is the riskiest, slowest path. A subtle evaluator bug becomes an authorization bypass. Instead we **build on Cedar, the open-source Rust library** (Apache-2.0, formally specified, with policy validation and analysis tooling). We write the parts nobody provides:
- the enforcement points;
- identity and group handling;
- policy CI;
- audit;
- the glue to Lakekeeper, Trino, Sail and SeaweedFS STS.

This is how Lakekeeper Plus works too: Cedar compiled into Lakekeeper through its authorizer trait. The difference is that ours is open and under our control.

## 3. Requirements (owner to confirm or extend)

- **R1** One policy model for namespaces, tables and views across catalog and engines. Row and column rules come later.
- **R2** Identity from Rauthy JWTs, including `groups`, used at decision time without manual syncing.
- **R3** Enforce in Lakekeeper: catalog API calls and *whether and what* storage credentials are vended (Phase D).
- **R4** Enforce in Trino for end users, through Trino's built-in OPA access-control plugin. It calls an HTTP decision API we implement, so there is no Trino fork. Row filters and column masks go through the same plugin later (verify in a spike).
- **R5** Sail: authenticate and authorize Spark Connect at a gateway in front of Sail (JWT checked against Rauthy's JWKS), and give Sail outbound tokens through a token broker.
- **R6** Storage: only short-lived, table-scoped SeaweedFS STS credentials; engines lose their static bucket-wide keys (Phase D).
- **R7** Audit: every allow and deny recorded with principal, action, resource, policy ID and reason.
- **R8** Policy as code in git: schema validation, unit tests and an analysis report in CI; changes go through PRs.
- **R9** Revocation takes effect within a stated bound (target: seconds), tested.
- **R10** Fail closed. Hardened UBI images, Rust, TLS everywhere, amd64 and arm64, our CVE gate, adversarial tests.
- **R11** Later: ClickHouse, a management UI or API, multi-tenant projects.

## 4. Architecture

```
            Rauthy (OIDC, groups)          policy repo (Cedar policies + schema, PR-reviewed)
                 |  JWKS / tokens                      | signed bundle
                 v                                     v
  +------------------------- datopsis-authz (Rust, embeds cedar-policy) -------------------+
  |  decision API  |  Trino OPA-compatible API  |  entity store (PostgreSQL, verify-full)  |
  |  audit stream (append-only)  |  policy loader (bundle hash pinned)  |  metrics         |
  +----------------------------------------------------------------------------------------+
       ^                         ^                              ^
       | authorizer crate        | OPA plugin (stock Trino)     | per-request check
  Lakekeeper (custom thin bin,   Trino                          Sail gateway (Rust, TLS, JWT)
  same lakekeeper crate)              \                           -> Sail on 127.0.0.1
       | vends table-scoped STS creds  \___ reads via Lakekeeper-vended creds
       v
  SeaweedFS STS (session policy = the decision)
```

Components, each its own small repo and hardened image:

1. **`datopsis-authz`**, the decision service. A Rust (axum/tonic) service embedding `cedar-policy`:
   - It loads a pinned, hash-verified policy bundle.
   - Entities come from JWT claims at request time (R2), plus a PostgreSQL entity store for resources and hierarchy.
   - It exposes a native decision API and an OPA-compatible API for Trino.
   - Every decision goes to the audit stream.
2. **Lakekeeper authorizer.** A crate implementing Lakekeeper's `Authorizer` trait by calling `datopsis-authz`, and a thin binary (like upstream `lakekeeper-bin`) that selects it. It's built in `lakekeeper-ubi` as an alternative binary from the same pinned Lakekeeper source; that's composition, not patching.
3. **Sail gateway.** A Rust gRPC/HTTP2 proxy that replaces nginx for Sail:
   - It terminates TLS and validates the JWT.
   - It authorizes each ExecutePlan.
   - It must keep answering HTTP/2 PINGs under backpressure. That might also remove the ~80 s reset; a spike will check.
4. **Token broker.** A tiny sidecar that holds Sail's client credentials and keeps its bearer-token file fresh.
5. **Policy toolkit.** A Cedar schema for the lakehouse, example policies, a CI action (validate, test, analyze) and bundle signing.

## 5. Phased plan, with go/no-go gates

- **C0 Interim (now).** OpenFGA as decided "for now":
  - Finish the evaluation PR's runtime tests (grant, deny, revoke, groups) to have a working baseline and a reference test suite.
  - **Recommendation:** don't build a production `openfga-ubi` image unless C1 fails. The C0 tests become the acceptance suite every backend must pass.
- **C1 Spikes,** evaluation only, each a pass/fail report:
  - **S1** Custom Lakekeeper binary with a Cedar authorizer: the authorizer trait's surface, coverage of the management API, and the C0 tests passing.
  - **S2** Trino's OPA plugin against a stub decision API: table, schema and column decisions, plus row-filter and mask support.
  - **S3** Sail gateway: JWT enforcement, streaming, and PINGs under backpressure (the ~80 s reset).
  - **S4** Rauthy `groups` mapped to Cedar entities, and revocation timing.
  - **Gate:** the owner decides whether to build. If S1 fails (trait too large or unstable), fall back to OpenFGA plus our own group sync, the gateway and Trino via OPA.
- **C2 MVP:**
  - `datopsis-authz`, the Lakekeeper authorizer and the Sail gateway as hardened images.
  - Namespace and table read/write policies, groups from Rauthy, audit, and the policy CI.
  - Integration test T13: C0 suite, Trino and Sail enforcement, revocation, and adversarial cases (forged, expired and wrong-audience tokens; policy-bundle tampering; decision-API spoofing).
- **C3 Phase D:** vending gated by decisions; table-scoped STS session policies; static engine keys removed; storage tests proving cross-table access is impossible.
- **C4 Extensions:** row filters and column masks in Trino, ClickHouse, a management API or UI, and multi-tenancy.

## 6. Risks and how we contain them

- **Owning a security-critical component.** Keep it small, embed a formally specified engine, require adversarial tests, and have the PoCs and tests for this work done by a local Claude Code child, since Codex refuses adversarial work.
- **Lakekeeper authorizer-trait churn.** Pin Lakekeeper, add a compile-and-test check for every Lakekeeper bump, and contribute upstream where it makes sense.
- **Trino OPA API compatibility.** Pin Trino and contract-test the plugin's requests.
- **Scope creep.** Each component is a narrow, independently tested repo. Nothing replaces Rauthy, Lakekeeper or Trino.
- **Availability.** The decision service is on the request path; it needs HA and caching with explicit TTLs, and it fails closed.

## 7. Decisions for the owner (asked one at a time)

1. Confirm or extend requirements R1–R11.
2. Build on the Cedar library (recommended) or another engine.
3. Project name and repo layout: one repo per component (recommended, like the image repos), or a monorepo.
4. Interim OpenFGA depth: evaluation only (recommended) or a hardened `openfga-ubi`.
5. Order: run spikes S1–S4 first (recommended) or go straight to the MVP.
6. License for the new code (Apache-2.0 suggested, matching the other repos).

## 8. Future capabilities (owner: R1–R11 complete for now; these are later options)

**Fine-grained rules apply only where queries pass through an engine we control.** Row filters, column masks and classification rules work in Trino, and later in the Sail gateway and ClickHouse. A client reading Parquet files directly (PyIceberg, or Sail via vended credentials) bypasses them. So any table carrying such rules must get **no direct storage credentials**: it is readable only through an enforcing engine. Every option below inherits this rule.

Each option lists its size (S/M/L), what it depends on, and its catch.

**Data governance**

1. **Data classification and tags** (M). Label namespaces, tables and columns, for example `pii`, `confidential` or `export-controlled`. Labels are stored as entity attributes and referenced by policies: "only `pii-readers` may read `pii` columns".
   - Depends on: the entity store, plus Trino column masks.
   - Catch: someone must keep labels correct; that's what (2) is for.
2. **Automatic classification** (L). Scan new tables and columns for patterns such as emails, card numbers and national IDs, and propose tags for an owner to confirm.
   - Depends on: (1), and a scanner job running in Trino.
   - Catch: false positives; never auto-grant, only auto-restrict.
3. **Lineage-aware classification** (L). Derived tables inherit their sources' tags.
   - Depends on: OpenLineage events from Trino and Spark, and a lineage store.
   - Catch: lineage capture is incomplete for ad-hoc copies.
4. **Retention, legal hold and deletion requests** (L).
   - Classification drives retention.
   - Legal hold blocks snapshot expiry and Object Lock release.
   - GDPR-style erasure workflows rewrite Iceberg tables.
   - Depends on: (1), and T11 maintenance.

**Access management**

5. **Attribute-based access, ABAC** (S–M). Decide on attributes such as department, region, clearance, project or device trust, not only groups. Cedar is ABAC-native.
   - Depends on: Rauthy claims, or an HR/directory attribute source.
6. **Row-level security and column masking** (M). Per-user filters, for example `region = user.region`, and masks or hashes on sensitive columns, enforced through Trino's OPA plugin.
   - Depends on: R4, (1) and the direct-read rule.
7. **Access requests and approvals** (M). A user requests access, the data owner approves or denies, and the grant is written with an expiry. Everything is audited, with email or Slack notifications.
   - Depends on: the entity store and a small API and UI.
8. **Just-in-time and time-bound grants** (S). Every grant can expire; access can be elevated temporarily with a reason.
   - Depends on: (7).
9. **Purpose-based access** (S). A declared purpose such as "fraud investigation" is carried in the session and checked by policy.
10. **Delegated ownership and stewardship** (M). Namespace owners grant within their area without a platform admin; stewards manage tags.
11. **Access reviews and recertification** (M). A periodic "who has access to what" report; owners re-certify, and anything not re-certified is revoked automatically.
12. **Break-glass access** (S). Emergency access with mandatory reason, alerting, short expiry and a post-incident review record.
13. **Separation of duties for policy changes** (S). Policy PRs need two reviewers, and the production bundle is signed by a separate key holder.
    - Needs an owner-approved GitHub setting change.

**Identity**

14. **External identity federation** (M). Rauthy brokers Entra ID, Google, GitHub or LDAP logins, and groups are mapped from the upstream provider.
    - Depends on: Rauthy's upstream-provider support (verify per provider).
15. **SCIM provisioning** (M). Users and groups are created and removed automatically from a corporate directory.
16. **Workload identity** (M). Services get SPIFFE-style identities or mTLS-bound tokens instead of shared client secrets.
    - Depends on: the PKI lifecycle work from Phase A.

**Assurance and operations**

17. **Policy simulation and "why was I denied?"** (S–M). What-if checks before merging a policy change, plus a user-facing explanation that cites the deciding policy ID.
18. **Policy analysis proofs** (M). Prove properties in CI with Cedar's analysis tooling, for example "no principal outside `pii-readers` can read a `pii` column".
19. **Tamper-evident audit and SIEM export** (M). A hash-chained audit log, shipped over OpenTelemetry or syslog to a SIEM, with retention per classification.
20. **Anomaly detection** (L). Alerts on unusual access, such as bulk reads, new locations or off-hours use.
    - Depends on: (19).
21. **Compliance evidence reports** (M). Map controls to evidence for frameworks such as SOC 2 or HIPAA, alongside container-hardening's STIG/SRG work.

**Platform**

22. **Multi-tenancy** (L). Projects or warehouses isolated per tenant, with tenant admins, per-tenant policies and storage prefixes.
23. **Self-service portal** (L). Browse the catalog, see your own permissions, request access, and view a table's tags and owners.
24. **External data sharing** (L). Share a table with a partner through a scoped, expiring identity and vended read-only credentials, fully audited.
25. **Per-classification encryption** (L). Per-table or per-tag encryption keys (KMS or Vault), and tokenization of the most sensitive columns.
26. **Quotas and rate limits** (S–M). Per-user or per-group query and data-scan limits.
27. **ClickHouse enforcement** (M). The same policies applied to ClickHouse as a third engine. Already listed as R11.

**Suggested grouping for later:** "governance basics" (1, 5, 6, 8, 12, 17) sits on top of the MVP with the best value for its size. (7, 10, 11) make it self-service. (19, 18, 13) give audit-grade assurance.

## 9. Diagrams rule

Every feature that changes the architecture updates `lakehouse-integration/docs/diagrams/*.svg` in the same PR, or in an immediately following docs PR. When `datopsis-authz` starts, add `docs/diagrams/lakehouse-authorization-architecture.svg` and keep it current with each capability above.
