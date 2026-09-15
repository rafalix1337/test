# ssm-org-migration-check

Read-only audit of an AWS account's Systems Manager setup, run **before** moving the
account to a different AWS Organization.

SSM documents themselves are not the problem. They are account-scoped, the account ID
does not change during the move, and everything under `Owned by me` comes out the other
side intact — content, versions, default version, tags and ARNs. Document sharing also
survives, because `ModifyDocumentPermission` targets explicit account IDs, never an
organization.

What breaks is configuration pinned to the **organization**. That is all this script
looks for.

## Reporting rules

The script was written to be quiet. It follows three rules:

1. **Evidence or nothing.** A finding is emitted only after the actual resource has been
   read and the offending token can be quoted back — `aws:PrincipalOrgID`, an `o-…` id,
   an `ou-…` id. Nothing is inferred from a naming convention.
2. **Must-fix or nothing.** Every finding is something that changes behaviour once the
   organization ID changes. No "you may also want to look at…", no severity ladder to
   triage.
3. **A failed check is never a pass.** Anything the credentials could not read is listed
   under *Could not be read*, with the API error, in the region where it happened.

## What it checks

All six checks are SSM resources, or resources that SSM configuration explicitly points at.

| Check | Evidence it needs |
| --- | --- |
| `document-content` | A self-owned document whose body contains an `o-…` / `ou-…` id — typically Automation `TargetLocations`. |
| `resource-data-sync` | `SyncSource.SourceType == AwsOrganizations`, read straight from the sync definition. |
| `bucket-policy` / `kms-key-policy` | The destination bucket and CMK of each Resource Data Sync, and the log bucket and CMK named in `SSM-SessionManagerRunShell` — fetched, then scanned for organization conditions. |
| `kms-key-policy` (SecureString) | CMKs actually referenced by `SecureString` parameters in this account. Keys under `alias/aws/*` are skipped: AWS-managed, no customer policy to break. |
| `vpc-endpoint-policy` | Interface endpoints whose service name ends in `.ssm`, `.ssmmessages` or `.ec2messages`, with an organization condition in the endpoint policy. |
| `delegated-administrator` | This account being registered as delegated administrator for `ssm.amazonaws.com`. Another account holding it is not reported. |

The SecureString check is the one worth running even if nothing else fires. It is the
only deferred failure on the list: nothing breaks at migration time, and then a restart
or a scale-out days later cannot decrypt its parameters.

### Deliberately not checked

- **CloudFormation StackSets.** A `StackSet-*` stack name says nothing about SSM, so
  flagging it would be a guess.
- **The target organization's SCPs.** They apply the instant the invitation is accepted
  and no API exposes them from the source account. Diff them by hand; the script will
  not pretend to cover it.

Every call is `Describe*` / `Get*` / `List*`. Nothing is mutated.

## Install

```bash
pip install boto3
# or, with no install:
uv run --with boto3 python ssm_migration_check.py --help
```

## Usage

```bash
# one region
python ssm_migration_check.py --profile my-aws-profile --region eu-west-1

# several regions in one pass — the report keeps them in separate sections
python ssm_migration_check.py --profile my-aws-profile --region eu-west-1,eu-central-1,us-east-1

# Markdown report for the migration ticket (default file: ./ssm-migration-report.md)
python ssm_migration_check.py --profile my-aws-profile --region eu-west-1 --markdown

# ...to a path of your choice, or straight to stdout
python ssm_migration_check.py --profile my-aws-profile --region eu-west-1 --markdown reports/prod.md
python ssm_migration_check.py --profile my-aws-profile --region eu-west-1 --markdown -

# machine-readable
python ssm_migration_check.py --profile my-aws-profile --region eu-west-1 --json > findings.json
```

### Parameters

| Flag | Default | Meaning |
| --- | --- | --- |
| `--profile` | standard credential chain | AWS named profile to use. |
| `--region` | the profile's configured region | Region, or comma-separated regions, to audit. |
| `--markdown [PATH]` | off; `ssm-migration-report.md` when passed bare | Also write a Markdown report. `-` prints it to stdout instead of the text report. |
| `--json` | off | Emit findings as JSON instead of the text report. |
| `--verbose` | off | Log progress to stderr. |
| `--fail-on` | `must-fix` | Exit non-zero on findings at this level or worse: `must-fix`, `unchecked`, `never`. |

### Markdown report

Grouped **by region**, not by severity: a scope table with the account, the current
organization ID and the number of items to fix, then one section per audited region
holding a `Resource | What is wrong | Fix` table. A region with nothing wrong says so.
A region where something could not be read gets a separate *Could not be read* table
underneath, so a partial run cannot be mistaken for a clean one.

Writing to a file does not replace the terminal output — you get both, with the path
logged to stderr. Only `--markdown -` suppresses the text report.

### Exit codes

- `0` — nothing to fix at or above `--fail-on`.
- `1` — findings at that level, or a fatal setup error (bad profile, unusable credentials).

## Required IAM permissions

Read-only; `SecurityAudit` or `ReadOnlyAccess` covers all of it.

```
sts:GetCallerIdentity
ssm:ListDocuments, ssm:GetDocument, ssm:DescribeParameters, ssm:ListResourceDataSync
ec2:DescribeVpcEndpoints
s3:GetBucketPolicy
kms:GetKeyPolicy
organizations:DescribeOrganization, organizations:ListDelegatedAdministrators
```

`organizations:*` only succeeds from the management account or a delegated admin.
`DescribeOrganization` is header metadata only; failing it costs you the organization ID
in the report, nothing else. Failing `ListDelegatedAdministrators` is a real blind spot
and is reported as such.

## Tests

No AWS account, credentials or network needed — every client is stubbed.

```bash
python -m unittest test_ssm_migration_check -v
# or
uv run --with boto3 python -m unittest test_ssm_migration_check -v
```

28 tests covering the detection logic, the pass/blind-spot distinction (a missing bucket
policy is a pass, an `AccessDenied` is not), SSM-only scoping (an org-pinned S3 endpoint
is ignored, an org-pinned `ssmmessages` endpoint is not), CMK deduplication and
AWS-managed-key skipping, and the region grouping in the report.
