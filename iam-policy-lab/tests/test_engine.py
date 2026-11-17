"""Six behaviour tests for evaluate(). Each one is a rule to implement.

Run: python -m pytest
"""

from iam_policy_lab.engine import evaluate

BUCKET_OBJ = "arn:aws:s3:::example-bucket/report.csv"
OTHER_BUCKET_OBJ = "arn:aws:s3:::other-bucket/report.csv"


def policy(*statements):
    """Build a policy dict in AWS format from one or more statements."""
    return {"Version": "2012-10-17", "Statement": list(statements)}


def stmt(effect, action, resource):
    return {"Effect": effect, "Action": action, "Resource": resource}


ALLOW_GET = stmt("Allow", "s3:GetObject", "arn:aws:s3:::example-bucket/*")


# 1. A matching Allow statement allows the request.
def test_allow_getobject_on_bucket_is_allowed():
    result = evaluate(policy(ALLOW_GET), "s3:GetObject", BUCKET_OBJ)
    assert result["decision"] == "Allow"


# 2. An action no statement mentions is implicitly denied.
def test_deleteobject_is_implicitly_denied():
    result = evaluate(policy(ALLOW_GET), "s3:DeleteObject", BUCKET_OBJ)
    assert result["decision"] == "Deny"


# 3. An explicit Deny wins even when an Allow also matches.
def test_explicit_deny_beats_allow():
    p = policy(
        ALLOW_GET,
        stmt("Deny", "s3:GetObject", "arn:aws:s3:::example-bucket/*"),
    )
    result = evaluate(p, "s3:GetObject", BUCKET_OBJ)
    assert result["decision"] == "Deny"


# 4. A wildcard action s3:Get* matches s3:GetObject.
def test_wildcard_get_star_matches_getobject():
    p = policy(stmt("Allow", "s3:Get*", "arn:aws:s3:::example-bucket/*"))
    result = evaluate(p, "s3:GetObject", BUCKET_OBJ)
    assert result["decision"] == "Allow"


# 5. s3:Get* does NOT match s3:PutObject.
def test_wildcard_get_star_does_not_match_putobject():
    p = policy(stmt("Allow", "s3:Get*", "arn:aws:s3:::example-bucket/*"))
    result = evaluate(p, "s3:PutObject", BUCKET_OBJ)
    assert result["decision"] == "Deny"


# 6. A resource in a different bucket does not match.
def test_different_bucket_resource_does_not_match():
    result = evaluate(policy(ALLOW_GET), "s3:GetObject", OTHER_BUCKET_OBJ)
    assert result["decision"] == "Deny"
