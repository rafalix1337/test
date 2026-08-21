# arn_delete.py

Delete AWS resources from a list of ARNs.

## Do you need a handler per resource type?

No. That is the point of this script.

AWS has no generic "delete whatever this ARN points at" API, but the
**Cloud Control API** gets close: one call, `delete_resource(TypeName, Identifier)`,
covers ~1100 resource types — the same type registry CloudFormation uses
(`AWS::EC2::Instance`, `AWS::RDS::DBInstance`, `AWS::S3::Bucket`, …).

The one thing AWS does *not* provide is a mapping from an ARN to a Cloud Control
`TypeName` + `Identifier`. So the only per-type code here is a lookup table:

```python
MAPPING = {
    ("ec2", "instance"): ("AWS::EC2::Instance",   ID,   10),
    ("rds", "db"):       ("AWS::RDS::DBInstance", ID,   10),
    ("iam", "role"):     ("AWS::IAM::Role",       LAST, 80),
}
#   ^ (service, resource-type) from the ARN
#                          ^ Cloud Control type   ^ how to derive the identifier
#                                                        ^ deletion order (low = first)
```

Adding support for a new resource type is **one line**, not a new delete handler.

## Install

```bash
pip install boto3
```

## Tests

```bash
python -m unittest -v test_arn_delete     # stdlib only
pytest test_arn_delete.py                 # if you prefer pytest
```

59 tests, no AWS calls and no credentials needed — the Cloud Control client is a
scripted fake, and `boto3` itself is stubbed when it is not installed, so the
suite runs anywhere. What it covers:

| Area | What is pinned down |
| --- | --- |
| ARN parsing | `/` vs `:` separators, earliest-separator-wins (the log-group case), leading-slash ARNs, malformed input |
| Identifier extraction | every awkward shape — SQS queue URL, SNS/ELBv2 full ARN, IAM path stripping, `:*` on log groups, ECS/EKS composite keys, hierarchical SSM names |
| Safety | S3 object ARNs and `log-stream` ARNs are rejected, never widened to their bucket/group |
| Ordering | instance → security group → VPC → log group, and duplicate collapsing |
| Input formats | flat file with comments, JSON list, tagging-API JSON, stdin, inline `--arn`, bad shapes |
| Region resolution | ARN region wins; bucket region looked up, cached, `us-east-1` normalized, failure falls back without raising |
| Status mapping | polling to SUCCESS, already-gone → `SKIPPED`, `UNSUPPORTED`, `FAILED`, `TIMEOUT` reporting its token, `--role-arn` forwarding |
| Pre-hooks | skipped without `--force`, RDS protection stripped before delete, bucket emptied in its own region, ECR short-circuit, a failing hook still attempts the delete |
| Plan & grace | plan printed before the first delete, no `GetResource` storm on the destructive path, Ctrl-C during the countdown deletes nothing (exit `130`), multi-account warning |

Credentials come from the usual chain (env vars, `~/.aws/credentials`, SSO,
instance/task role). `--profile` and `--region` are passed through to `boto3.Session`.

## Usage

```
python arn_delete.py [file] [--arn ARN]... [options]
```

### Invocations

```bash
# 1. Dry run (the DEFAULT — nothing is ever deleted without --execute)
python arn_delete.py arns.txt

# 2. Dry run that also verifies each resource really exists (read-only GetResource)
python arn_delete.py arns.txt --check

# 3. Actually delete — prints the full target list, waits 10s, then deletes
python arn_delete.py arns.txt --execute

# 3b. Longer window to eyeball the list before it goes
python arn_delete.py arns.txt --execute --grace 30

# 3c. No countdown at all (unattended / CI)
python arn_delete.py arns.txt --execute --grace 0

# 4. Delete, clearing whatever blocks deletion first
#    (deletion protection on RDS/ALB, API termination on EC2, non-empty S3/ECR)
python arn_delete.py arns.txt --execute --force

# 5. Ad-hoc, without a file
python arn_delete.py --arn arn:aws:ec2:eu-central-1:111122223333:instance/i-0abc --execute

# 6. Several inline ARNs
python arn_delete.py --arn arn:aws:s3:::bucket-a --arn arn:aws:s3:::bucket-b --execute

# 7. Mix a file with extra inline ARNs
python arn_delete.py arns.txt --arn arn:aws:sqs:eu-west-1:111122223333:my-queue --execute

# 8. Let Cloud Control assume a dedicated role for the deletions
python arn_delete.py arns.txt --execute --role-arn arn:aws:iam::111122223333:role/Deleter

# 9. Non-default profile, fallback region for region-less ARNs, shorter per-resource timeout
python arn_delete.py arns.txt --execute --profile sandbox --region eu-central-1 --timeout 600
```

### Options

| Flag | Meaning |
| --- | --- |
| `file` | Flat text or JSON list of ARNs (see [Input formats](#input-formats)); `-` reads stdin |
| `--arn ARN` | Inline ARN, repeatable; combines with `file` |
| `--execute` | Actually delete. Without it the script only prints the plan |
| `--dry-run` | Explicitly force a dry run (the default; mutually exclusive with `--execute`) |
| `--check` | In a dry run, probe every target with a read-only `GetResource` |
| `--force` | Run pre-hooks that clear deletion blockers before deleting |
| `--grace SECONDS` | Countdown before deletion starts, so you can Ctrl-C out (default `10`, `0` disables) |
| `--role-arn` | IAM role passed to Cloud Control API (needs `iam:PassRole`) |
| `--profile` | AWS profile |
| `--region` | Fallback region for ARNs that carry none |
| `--timeout` | Max seconds to wait for one resource to finish deleting (default 1800) |

## Input formats

The format is detected from the first non-whitespace character of the file, so
you can hand it whichever you already have.

### 1. Flat text — one ARN per line

`#` starts a comment, blank lines are ignored, surrounding whitespace is trimmed.

```
# prod teardown, ticket OPS-1234
arn:aws:ec2:eu-central-1:111122223333:instance/i-0abc123
arn:aws:rds:eu-central-1:111122223333:db:prod-db-1
arn:aws:s3:::my-test-bucket
arn:aws:logs:eu-west-1:111122223333:log-group:/aws/lambda/my-fn:*   # keep? no
```

### 2. JSON — a plain list of ARNs

```json
["arn:aws:sqs:eu-west-1:111122223333:q1", "arn:aws:sns:eu-west-1:111122223333:t1"]
```

### 3. JSON — AWS tooling output, unmodified

Anything shaped like `{"<list key>": [{"ResourceARN": "..."}]}` works, which
covers the Resource Groups Tagging API directly — the usual way to *find* the
things you want to delete:

```bash
# everything tagged env=sandbox, deleted without hand-editing a list
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=env,Values=sandbox > sandbox.json

python arn_delete.py sandbox.json            # inspect the plan
python arn_delete.py sandbox.json --execute
```

Recognized list keys: `ResourceTagMappingList`, `Resources`, `arns`, `Arns`,
`ARNs`. Recognized per-item ARN keys: `ResourceARN`, `Arn`, `ARN`, `arn`.

### 4. stdin

Pass `-` as the filename to pipe either format in:

```bash
aws resourcegroupstaggingapi get-resources --tag-filters Key=env,Values=sandbox \
  | python arn_delete.py - --execute

# or narrow it down with jq first
aws resourcegroupstaggingapi get-resources --tag-filters Key=env,Values=sandbox \
  | jq '[.ResourceTagMappingList[].ResourceARN | select(startswith("arn:aws:ec2"))]' \
  | python arn_delete.py - --execute
```

### 5. No file at all

```bash
python arn_delete.py --arn arn:aws:s3:::bucket-a --arn arn:aws:s3:::bucket-b --execute
```

`--arn` combines with a file; duplicate ARNs are collapsed automatically.

## Safety: the plan is always printed first

`--execute` never deletes straight away. It prints every resolved target — type,
account, the region the call will actually land in, and identifier — plus any ARN
it could not map, then summarizes the blast radius and counts down:

```
ABOUT TO DELETE 3 resource(s) - THIS IS IRREVERSIBLE
 ord  type                                account        region          identifier
------------------------------------------------------------------------------------
  10  AWS::EC2::Instance                  111122223333   eu-central-1    i-0abc123
  20  AWS::S3::Bucket                     -              eu-west-1       my-bucket
  90  AWS::EC2::VPC                       999988887777   eu-central-1    vpc-0dead
  --  UNRECOGNIZED ARN: bogus-arn  (not a valid ARN: 'bogus-arn')

  accounts: 111122223333, 999988887777
  regions:  eu-central-1, eu-west-1
  *** WARNING: 2 DIFFERENT ACCOUNTS in one run ***

  note: 1 unrecognized ARN(s) above will be SKIPPED

  Deleting in   7s ... press Ctrl-C to abort
```

The account column and the multi-account warning are the cheapest guard against
the worst failure mode: a list assembled from the wrong environment. Regions are
resolved for real here (including the `GetBucketLocation` lookup for S3), so the
column shows where each call will land rather than what the ARN happens to say.

Ctrl-C during the countdown exits `130` and deletes nothing. Ctrl-C *after* it
starts stops before the next resource — anything already deleted stays deleted,
and the script says so; re-running picks up the rest (already-gone resources come
back as `SKIPPED`).

Set `--grace 0` for unattended runs where there is nobody to press Ctrl-C.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Everything succeeded (dry run: all ARNs recognized) |
| `1` | At least one failure, or at least one unrecognized ARN |
| `2` | Bad command line (argparse) |
| `130` | Aborted with Ctrl-C |

A dry run returns `1` when any ARN could not be mapped — so it works as a CI gate
before you let the destructive run happen.

## Deletion order

Resources are sorted by the `order` value in `MAPPING`, lowest first. Leaves go
before the infrastructure they sit on:

```
 1  CloudFormation stack        ← if it exists, delete the stack, not its contents
 5  ASG, CloudWatch alarm
10  EC2 instance, Lambda, RDS instance, ECS service, ALB, SQS, SNS, DynamoDB
20  EBS volume, S3 bucket, ECR repo, RDS cluster, target group
30  ENI
40  NAT gateway
45  Elastic IP
50  ECS/EKS cluster
60  security group, DB subnet group
70  subnet, route table
75  internet gateway, instance profile
80  VPC, IAM role/user, hosted zone
85  IAM managed policy
90  secret, SSM parameter
95  log group
```

Without this, deleting a VPC before its security groups gives you
`DependencyViolation`. Deletion is sequential, one resource at a time — slower
than fanning out, but ordering is the whole point, so it is not parallelized.

## `--force` pre-hooks

Cloud Control will not clear these for you, so `--force` does it first:

| Type | What the pre-hook does |
| --- | --- |
| `AWS::S3::Bucket` | Deletes all objects and object versions (a non-empty bucket cannot be deleted) |
| `AWS::RDS::DBInstance` | `DeletionProtection = false` |
| `AWS::RDS::DBCluster` | `DeletionProtection = false` |
| `AWS::EC2::Instance` | Clears `DisableApiTermination` and `DisableApiStop` |
| `AWS::ECR::Repository` | `delete_repository(force=True)` — deletes natively, skips Cloud Control |
| `AWS::ElasticLoadBalancingV2::LoadBalancer` | `deletion_protection.enabled = false` |

A pre-hook that fails only warns; the deletion is still attempted.

## Adding a resource type

1. Find the Cloud Control type name:

   ```bash
   aws cloudformation list-types --visibility PUBLIC --type RESOURCE \
     --query 'TypeSummaries[?contains(TypeName, `Beanstalk`)].TypeName'
   ```

2. Check what it uses as its primary identifier — this is the part that bites:

   ```bash
   aws cloudformation describe-type --type RESOURCE \
     --type-name AWS::ElasticBeanstalk::Environment \
     --query Schema --output text | python -c \
     'import json,sys; print(json.load(sys.stdin)["primaryIdentifier"])'
   ```

3. Add one line to `MAPPING`, picking an identifier extractor:

   | Extractor | Yields | Used by |
   | --- | --- | --- |
   | `ID` | everything after the resource type | EC2, RDS, Lambda, DynamoDB |
   | `FULL` | the entire ARN | SNS, ELBv2, Step Functions, Secrets Manager |
   | `LAST` | last `/`-separated segment | IAM (paths), OpenSearch, API Gateway |
   | `LOG_GROUP` | log group name with a trailing `:*` stripped | CloudWatch Logs |
   | custom fn | anything | SQS (queue URL), ECS service (`cluster\|name`) |

4. Verify with `--check` before running `--execute`.

## Caveats — read before pointing this at production

1. **Identifiers are not uniformly the ARN.** SQS wants the *queue URL*.
   SNS, ELBv2, Step Functions and Secrets Manager want the *full ARN*. ECS
   services and EKS node groups use a composite key (`cluster|name`). This
   irreducible per-service knowledge is exactly what the extractor functions
   hold — always confirm a newly added type with `--check` first.

2. **Region-less ARNs.** S3 and IAM ARNs carry no region. IAM is global so any
   region works; for S3 the script looks the bucket's region up via
   `GetBucketLocation` (cached) rather than guessing, because a bucket must be
   addressed in its own region. Everything else falls back to `--region` or the
   session region, then `us-east-1`.

3. **Not every type supports DELETE** through Cloud Control. Those come back as
   `UNSUPPORTED` rather than failing silently — then add a native hook, following
   the `_hook_ecr` pattern (do the work, raise `_AlreadyDone`).

4. **KMS keys cannot be deleted**, only scheduled for deletion
   (`ScheduleKeyDeletion`, 7–30 days). Deliberately absent from `MAPPING`; add it
   as a native hook if you need it.

5. **IaC-managed resources.** If these resources came from CloudFormation or
   Terraform, deleting them by ARN desynchronizes the state and the next
   `apply`/`deploy` will try to recreate or fail. Delete the stack or run
   `terraform destroy` instead — `AWS::CloudFormation::Stack` is in `MAPPING`
   with order `1` for exactly this case.

6. **Sub-resource ARNs are rejected, not widened.** `arn:aws:s3:::bucket/key`
   is *not* treated as its bucket, and a `log-stream` ARN is not treated as its
   log group; both are reported as unrecognized. Deleting a whole bucket because
   someone pasted an object ARN would be a very bad default.

7. **IAM permissions.** Cloud Control calls the underlying service APIs, so your
   principal needs the real destructive actions (`ec2:TerminateInstances`,
   `rds:DeleteDBInstance`, `s3:DeleteBucket`, …), plus
   `cloudformation:DescribeType` if you use step 2 above, plus `iam:PassRole`
   when using `--role-arn`. `--force` additionally needs `s3:DeleteObject*`,
   `rds:ModifyDB*`, `ec2:ModifyInstanceAttribute`,
   `elasticloadbalancing:ModifyLoadBalancerAttributes`, `ecr:DeleteRepository`.

8. **Async operations.** Cloud Control deletes are asynchronous; the script polls
   `GetResourceRequestStatus` with backoff up to `--timeout`. A slow RDS cluster
   can exceed the default 30 minutes — a `TIMEOUT` result prints the request
   token so you can keep polling manually:

   ```bash
   aws cloudcontrol get-resource-request-status --request-token <token>
   ```

9. **Cloud Control does not do dependency discovery.** It deletes what you name,
   nothing more. The `order` column handles the common dependency chains, but
   e.g. an ENI held by a service you did not list will still block its subnet.
