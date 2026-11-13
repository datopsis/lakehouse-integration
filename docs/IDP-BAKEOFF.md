# Identity provider bake-off (Phase B)

Evaluation in progress. No IdP is qualified yet. This workflow is independent of
the required Integration check and does not change its configuration or pins.

The pinned Lakekeeper 0.13.4 serves plaintext TCP only. The Phase A document
explicitly leaves a loopback proxy exception undecided. This evaluation obeys
the stronger instruction that tokens never travel in plaintext: it tests the
transport boundary without a token and marks dependent assertions blocked.
It does not pass bearer tokens through a plaintext proxy backend.

The independent native amd64/arm64 workflow tests official upstream images:
Kanidm 1.12.0, Rauthy 0.37.2, and Keycloak 26.8.2 (control and fallback).
OCI index digests are in evaluation/idp/providers.py; the main image lock is
unchanged. Per-run certificates, passwords, client secrets and tokens stay in
ignored runtime files. Only redacted reports are uploaded.

Actual run links, comparison tables, source survey and recommendation will be
added after inspecting Actions logs and artifacts. A blocked assertion is not
a pass; the separate evaluation check intentionally fails incomplete qualification.
