"""Optional STS diagnostic in its own warehouse; no main-path changes."""

import copy
import json
from urllib.parse import urlsplit

import botocore.session
import pyarrow as pa
from botocore.exceptions import ClientError
from common import secret


def evaluate(catalog, operator, tuples):
    storage = catalog.storage
    session = botocore.session.get_session()
    options = dict(
        endpoint_url=storage.endpoint,
        region_name="local",
        aws_access_key_id=storage.access,
        aws_secret_access_key=storage.password,
        verify=str(storage.ca),
    )
    iam = session.create_client("iam", **options)
    role = iam.create_role(
        RoleName="phase-d",
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}],
            }
        ),
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName="phase-d",
        PolicyName="warehouse",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": ["arn:aws:s3:::warehouse", "arn:aws:s3:::warehouse/*"],
                    }
                ],
            }
        ),
    )
    # Probe the actual pinned STS implementation before asking Lakekeeper to vend.
    sts = session.create_client("sts", **options)
    credentials = sts.assume_role(RoleArn=role, RoleSessionName="preflight", DurationSeconds=900)[
        "Credentials"
    ]
    for field in ("AccessKeyId", "SecretAccessKey", "SessionToken"):
        secret(credentials[field])
    headers = {"Authorization": "Bearer " + operator}
    body = catalog.http.json(
        "POST",
        catalog.base + "/management/v1/warehouse",
        headers=headers,
        statuses=(200, 201),
        json={
            "warehouse-name": "phase-d",
            "storage-profile": {
                "type": "s3",
                "bucket": "warehouse",
                "key-prefix": "phase-d",
                "region": "local",
                "sts-enabled": True,
                "sts-role-arn": role,
                "sts-token-validity-seconds": 900,
                "flavor": "s3-compat",
                "endpoint": storage.endpoint,
                "path-style-access": True,
            },
            "storage-credential": {
                "type": "s3",
                "credential-type": "access-key",
                "access-key-id": storage.access,
                "secret-access-key": storage.password,
            },
        },
    )
    isolated = copy.copy(catalog)
    isolated.warehouse, isolated.warehouse_id = "phase-d", body["warehouse-id"]
    admin = isolated.pyiceberg(operator)
    for ns in ("allowed", "denied"):
        admin.create_namespace(ns)
        table = admin.create_table(ns + ".sample", schema=pa.schema([pa.field("id", pa.int64())]))
        table.append(pa.Table.from_pylist([{"id": 1}]))
    ns_id = admin.load_namespace_properties("allowed")["namespace_id"]
    tuples("user:oidc~lakekeeper", "select", "namespace:" + ns_id)
    token = catalog.provider.token()
    headers = {
        "Authorization": "Bearer " + token,
        "X-Iceberg-Access-Delegation": "vended-credentials",
    }
    base = catalog.base + f"/catalog/v1/{isolated.warehouse_id}/namespaces/"
    allowed = catalog.http.json("GET", base + "allowed/tables/sample", headers=headers)
    cfg = allowed["config"]
    for field in ("s3.access-key-id", "s3.secret-access-key", "s3.session-token"):
        secret(cfg[field])
    s3 = session.create_client(
        "s3",
        endpoint_url=storage.endpoint,
        region_name="local",
        verify=str(storage.ca),
        aws_access_key_id=cfg["s3.access-key-id"],
        aws_secret_access_key=cfg["s3.secret-access-key"],
        aws_session_token=cfg["s3.session-token"],
    )
    key = urlsplit(allowed["metadata-location"]).path.lstrip("/")
    assert s3.get_object(Bucket="warehouse", Key=key)["Body"].read()
    other = urlsplit(admin.load_table("denied.sample").metadata_location).path.lstrip("/")

    def denied(fn):
        try:
            fn()
        except ClientError as exc:
            assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 403
            assert exc.response["Error"]["Code"] == "AccessDenied", exc.response
            return "403 AccessDenied"
        raise AssertionError("Downscoped storage request unexpectedly allowed")

    checks = {
        "other_table": denied(lambda: s3.get_object(Bucket="warehouse", Key=other)),
        "write": denied(
            lambda: s3.put_object(Bucket="warehouse", Key=key + ".forbidden", Body=b"denied")
        ),
    }
    response = catalog.http.request("GET", base + "denied/tables/sample", headers=headers)
    assert response.status_code in (403, 404), (response.status_code, response.text)
    assert "s3.secret-access-key" not in response.text
    return {
        "read_own_metadata": True,
        "s3_denials": checks,
        "denied_vending_status": response.status_code,
        "scope": "Separate phase-d warehouse; issued credential expiry/revocation not tested",
    }
