# IAM Policy Lab

A small local Python program that reads an AWS IAM policy (JSON) and answers:
**is this request allowed or denied, and why?** — showing each step.

## The problem
IAM permission rules are hard to read. Wildcards, multiple statements, and
Allow/Deny mixing make it easy to misjudge what a policy grants. When people
cannot read a policy with confidence, they tend to grant too much access.

## The solution
A command-line tool that takes:
- a policy file in real AWS JSON format, and
- a request: one **action** (e.g. `s3:GetObject`) and one **resource ARN**
  (e.g. `arn:aws:s3:::my-bucket/report.csv`)

and prints the decision (**Allow** or **Deny**) plus a step-by-step trace of
which statements matched and why.

## Scope of v1
v1 handles only:
- `Effect` (`Allow` / `Deny`)
- `Action`
- `Resource`
- `*` wildcards in Action and Resource

Decision rules in v1:
1. **Explicit deny beats allow.** If any matching statement says `Deny`, the answer is Deny.
2. **Allow** if at least one matching statement says `Allow` and none say `Deny`.
3. **Implicit deny is the default.** If nothing matches, the answer is Deny.

Not in v1: `Condition`, `NotAction`, `NotResource`, `Principal`, multiple
policies, permission boundaries, SCPs, `?` wildcards, policy variables.

## Safety
Runs only on local files. No AWS account, no credentials, no network calls.

## Usage
```bash
cd iam-policy-lab
python -m iam_policy_lab.cli \
  --policy policies/s3-read-one-bucket.json \
  --action s3:GetObject \
  --resource arn:aws:s3:::example-bucket/report.csv
```

## Tests
```bash
pip install -r requirements-dev.txt
python -m pytest
```
The tests are expected to **fail** until `evaluate()` in
`iam_policy_lab/engine.py` is written. Each passing test = one rule implemented.

## Status
Skeleton only. Decision logic: not yet written (owner is writing it by hand).
