"""The decision engine. This is the part YOU write.

Contract (the tests rely on this shape):

    evaluate(policy, action, resource) -> dict with two keys:
        "decision": the string "Allow" or "Deny"
        "trace":    a list of strings, one per step, explaining the decision

`policy` is the Python dict you get from json.load() on an AWS policy file.
`action` is a string like "s3:GetObject".
`resource` is a string like "arn:aws:s3:::example-bucket/report.csv".
"""


def evaluate(policy: dict, action: str, resource: str) -> dict:
    # TODO (mine to write): the matching and decision logic.
    #
    # Questions to answer before typing any code:
    #   - In AWS JSON, "Statement" can be a single object OR a list. Same for
    #     "Action" and "Resource". How will I handle both shapes?
    #   - How does "*" in "s3:Get*" match "s3:GetObject"? Is AWS action
    #     matching case-sensitive? (Check the AWS docs; do not guess.)
    #   - In what order do the three rules apply: explicit deny, allow,
    #     implicit deny?
    #   - What should each trace line say so a reader can follow the decision?
    raise NotImplementedError("evaluate() is not written yet")
