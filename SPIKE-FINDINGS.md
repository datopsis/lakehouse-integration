# Lakehouse feasibility spike — in progress

This branch is throwaway feasibility evidence, not the Phase 3 test or a release qualification.
The four source commits are fixed in `spike/pins.json`; no upstream repository is modified.

The first GitHub Actions experiment is being prepared. No runtime result is claimed yet.

## Known source-level constraints

- Lakekeeper's pinned build emits neither the OCI revision label nor the artifact-lock hash label.
- SeaweedFS emits an OCI revision label and upstream commit label, but no artifact-lock hash label.
- The harness records these exact missing-label gaps, checks all emitted labels, and additionally
  compares the image's Lakekeeper/SeaweedFS binary SHA-256 with the reviewed lock. It does not
  manufacture labels or claim this is equivalent to complete image provenance.
- Lakekeeper login is off (owner-approved gap). Trino uses the image's explicit isolated-test
  insecure mode, with no port publication. TLS and Trino login are unqualified.
- The pinned Trino draft PR #2 remains blocked by its vulnerability gate. The source and gate
  are unchanged. Prior amd64 evidence: https://github.com/datopsis/trino-ubi/actions/runs/42823620083/job/129855104023.
- SeaweedFS uses four separated roles, durable master/volume/filer mounts, and a read-only
  mounted static S3 identity. No internal listener is exposed. This is one-host feasibility,
  not replicated production durability or a security qualification.

## Files

- `.github/workflows/feasibility.yml`: amd64 runner, read-only token, full action SHAs, timeout.
- `spike/build.py`: exact-SHA fetch/HEAD checks, repository-owned builds, image verification.
- `spike/compose.yaml`: minimal hardened topology; internal network; named persistent volumes.
- `spike/trino/`: server configuration and Iceberg REST/S3 catalog with environment secret references.
- `spike/probe.py`: random credentials, bootstrap, SQL, cross-engine reads, delegation probes, recreation.
- `spike/cleanup.py`: redacted diagnostics and teardown; generated secrets are excluded from artifacts.

Findings, timings, run links and Phase 3 recommendations will replace this provisional record
once the experiment has run.
