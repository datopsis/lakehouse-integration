# Authorization backend evaluation (Phase C)

Evaluation in progress. No backend is qualified and no runtime results are claimed.
The workflow is manual-only and independent of the required Integration check.

The pinned Lakekeeper 0.13.4 source (`9bd377162345b64a716f0a4fcffe4e7e7f3c7534`)
implements OpenFGA and allow-all in the open-source binary. Built-in Cedar is a
Lakekeeper Plus feature. Cedar itself is Apache-2.0 open source; Amazon Verified
Permissions is excluded. The OpenFGA authorizer does not consume OIDC token roles.
