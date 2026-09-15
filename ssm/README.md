# ssm-org-migration-check

Read-only audit of an AWS account's Systems Manager setup, run **before** moving the
account from one AWS Organization to another.

SSM documents themselves are not the problem: they are account-scoped, the account ID
does not change during the move, and `Owned by me` documents come out the other side
intact — content, versions, default version, tags and ARNs. Document sharing also
survives, because `ModifyDocumentPermission` targets explicit account IDs (or `All`),
never an organization.

What breaks is everything wired to the *organization*. This script finds it.

## What it checks

| Check | Severity | Why it matters |
| --- | --- | --- |
| `document-content` | HIGH | Self-owned documents whose body embeds `o-…` / `ou-…` ids — typically Automation `TargetLocations`. |
| `resource-data-sync` | HIGH | `SyncFromSource` syncs with source type `AwsOrganizations` stop aggregating the moment the org changes. |
| `delegated-administrator` | HIGH | Delegated admin for `ssm.amazonaws.com` (Change Manager, Explorer) is org-scoped and is lost. |
| `vpc-endpoint-policy` | HIGH | Policies on the `ssm`, `ssmmessages` and `ec2messages` interface endpoints that use `aws:PrincipalOrgID` — Session Manager and the agent get `AccessDenied` after the move. |
| `bucket-policy` / `kms-key-policy` | HIGH | Session Manager log bucket and encryption key, resolved from `SSM-SessionManagerRunShell`, pinned to the current org id. |
| `quick-setup-association` | HIGH | State Manager associations created by Quick Setup from the management account. |
| `service-managed-stack` | HIGH / MEDIUM | `StackSet-*` stack instances pushed from an organization StackSet — leaving the OU removes or orphans them, and Quick Setup rides on exactly this. |
| `document-sharing` | MEDIUM / LOW | Documents shared publicly, or shared with accounts that are in the current org and become cross-org after the move. |
| `public-sharing-setting` | LOW | Whether public document sharing is enabled, which the target org may forbid by SCP. |
| `organization`, `documents` | INFO | Context: current org id, management vs member, document count. |

Not covered, because no API exposes it from the source account: the **SCPs of the target
organization**. Those apply the instant the account is invited, and an SCP denying
`ssm:*` or restricting regions is the most common post-migration surprise. Diff the two
organizations' policies by hand.

Every call is `Describe*` / `Get*` / `List*`. The script never mutates anything.

## Install

```bash
pip install boto3
# or, with no install:
uv run --with boto3 python ssm_migration_check.py --help
```

## Usage

```bash
# audit one region with a named profile
python ssm_migration_check.py --profile kitopi-prod --region eu-west-1

# several regions in one pass
python ssm_migration_check.py --profile kitopi-prod --region eu-west-1,eu-central-1,us-east-1

# machine-readable, for a pipeline
python ssm_migration_check.py --profile kitopi-prod --region eu-west-1 --json > findings.json

# write a Markdown report (default file: ./ssm-migration-report.md)
python ssm_migration_check.py --profile kitopi-prod --region eu-west-1 --markdown

# ...or to a path of your choice, or straight to stdout
python ssm_migration_check.py --profile kitopi-prod --region eu-west-1 --markdown reports/prod.md
python ssm_migration_check.py --profile kitopi-prod --region eu-west-1 --markdown - | pbcopy
```

### Parameters

| Flag | Default | Meaning |
| --- | --- | --- |
| `--profile` | standard credential chain | AWS named profile to assume. |
| `--region` | the profile's configured region | Region, or comma-separated regions, to audit. |
| `--json` | off | Emit findings as JSON instead of the grouped text report. |
| `--markdown [PATH]` | off; `ssm-migration-report.md` when passed bare | Also write a Markdown report. `-` prints it to stdout instead of the text report. |
| `--verbose` | off | Log progress to stderr. |
| `--fail-on` | `high` | Exit non-zero when a finding of this severity or worse exists. Use `never` to always exit 0. |

### Markdown report

`--markdown` produces a self-contained hand-off document: scope (account, current
organization id, profile, regions, UTC timestamp), a severity summary with an explicit
go / no-go line, one table per severity, a "not covered by this report" section naming
the target organization's SCPs and any checks that were skipped, and a suggested order
of work. It is meant to be attached to the migration ticket rather than read in a
terminal.

Writing to a file does not replace the terminal output — you get both, with the file
path logged to stderr. Only `--markdown -` suppresses the text report.

### Exit codes

- `0` — no finding at or above `--fail-on`.
- `1` — at least one such finding, or a fatal setup error (bad profile, unusable credentials).

## Required IAM permissions

A read-only role is enough; `SecurityAudit` or `ReadOnlyAccess` covers all of it.

```
sts:GetCallerIdentity
ssm:ListDocuments, ssm:GetDocument, ssm:DescribeDocumentPermission,
ssm:ListResourceDataSync, ssm:ListAssociations, ssm:GetServiceSetting
ec2:DescribeVpcEndpoints
s3:GetBucketPolicy
kms:GetKeyPolicy
cloudformation:ListStacks
organizations:DescribeOrganization, organizations:ListAccounts,
organizations:ListDelegatedAdministrators
```

Missing permissions do not abort the run. Each unreachable check is reported as an `INFO`
finding saying it was skipped, so a partial audit is still readable — but treat those as
blind spots, not as clean results. The `organizations:*` calls only succeed from the
management account or a delegated admin; from a member account the sharing check simply
cannot tell which shared accounts are in-org, and downgrades to listing them.

## Suggested order of work

1. Run this in every region the account actually uses.
2. Fix every `HIGH` before the move — the `aws:PrincipalOrgID` ones in particular, since
   they fail closed.
3. Grep your Terraform for the same thing, which this script cannot see:
   `grep -rE 'PrincipalOrgID|ResourceOrgID|\bo-[a-z0-9]{10,}' <infra-repo>`
4. Diff source and target organization SCPs.
5. Re-run after the move with `--fail-on medium` to confirm nothing regressed, and
   re-provision Quick Setup / Resource Data Sync from the new organization.
