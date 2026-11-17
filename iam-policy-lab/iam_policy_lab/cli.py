"""Command-line entry point.

Loads a policy JSON file and a request (action + resource ARN), then asks
engine.evaluate() for a decision. Until evaluate() exists, prints a stub trace.
"""

import argparse
import json
import sys

from iam_policy_lab.engine import evaluate


def load_policy(path: str) -> dict:
    """Read a policy JSON file from disk and return it as a dict."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Explain an IAM policy decision.")
    parser.add_argument("--policy", required=True, help="Path to a policy JSON file")
    parser.add_argument("--action", required=True, help="e.g. s3:GetObject")
    parser.add_argument("--resource", required=True, help="e.g. arn:aws:s3:::bucket/key")
    args = parser.parse_args(argv)

    policy = load_policy(args.policy)

    print(f"Policy:   {args.policy}")
    print(f"Action:   {args.action}")
    print(f"Resource: {args.resource}")
    print("Trace:")

    try:
        result = evaluate(policy, args.action, args.resource)
    except NotImplementedError:
        print("  [stub] loaded policy with keys:", ", ".join(policy.keys()))
        print("  [stub] evaluate() not written yet - no decision made")
        print("Decision: (none)")
        return 2

    for step in result["trace"]:
        print(f"  - {step}")
    print(f"Decision: {result['decision']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
