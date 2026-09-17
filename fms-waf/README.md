# fms-waf-report

Read-only inventory of the AWS WAF web ACLs that **Firewall Manager** pushes into an
account, rendered as a Markdown report with one table per region.

Firewall Manager names the web ACLs it creates `FMManagedWebACLV2-<policy>-<epoch>`, so
the prefix is the handle you have on them from inside a member account. That is what this
script keys on.

## What it reports

Per region, per web ACL:

| Section | Contents |
| --- | --- |
| Region summary | one row per web ACL: policy name parsed out of the ACL name, WCU capacity, default action, rule count, associated-resource count, allowed / counted / blocked |
| Rules | every rule in evaluation order, split into three stages — `pre-process (Firewall Manager)`, `account rules`, `post-process (Firewall Manager)` — with statement type, a readable summary of the statement, the effective action, and per-rule request counts |
| Associated resources | ALB, API Gateway, AppSync, Cognito, App Runner, Verified Access and Amplify ARNs for regional scope; CloudFront distributions with their aliases for global scope |
| Observations | web ACL associated with nothing, no traffic in the window, rule groups sitting in count mode, `ManagedByFirewallManager` gone false, retrofitted ACLs |

The three stages matter more than they look. Rules in the pre- and post-process stages come
from the Firewall Manager policy and **cannot be edited from this account** — a local change
is reverted on the next compliance run. Your own rules sit in the middle and cannot be
promoted above them.

The other thing worth reading carefully is the action column. An `override: count` or `count`
on a rule group means it matches and reports but **blocks nothing** — a web ACL can look fully
configured, be correctly associated, and still pass everything through. The report calls this
out per ACL instead of leaving it to be spotted in a wide table.

## Regions

`global` is not a region — it is WAF scope `CLOUDFRONT`, which exists only in `us-east-1`.
The script maps the label to the right scope and endpoint, and labels the section `global`
so the report reads the way the console does. Everything else is scope `REGIONAL`.

Default region list: `global, us-east-1, us-west-2, eu-central-1, eu-west-2`.

## Traffic numbers

Counts come from CloudWatch, namespace `AWS/WAFV2`, metrics `AllowedRequests`,
`CountedRequests` and `BlockedRequests`, summed over the window with `Sum`.

The dimension set WAF publishes differs between scopes and has changed over time, so the
script does not guess it: it calls `ListMetrics` filtered on the `WebACL` dimension, learns
the real dimension sets, and only falls back to `WebACL` + `Rule` + `Region` if that comes
back empty. Web-ACL totals are the `Rule=ALL` series; per-rule numbers use each rule's own
`VisibilityConfig.MetricName`.

Two caveats:

- A rule that never matched publishes no metric and shows as `0`. Absent and zero are not
  distinguishable here.
- `allowed + counted + blocked` need not equal total requests — CAPTCHA and challenge
  outcomes are counted separately by WAF.

## Install

```bash
pip install boto3
# or, with no install:
uv run --with boto3 python fms_waf_report.py --help
```

## Usage

```bash
# the five default regions, last 7 days, report to fms-waf-report.md
python fms_waf_report.py --profile my-profile

# one region, 30-day window, to stdout
python fms_waf_report.py --profile my-profile --regions eu-west-1 --days 30 -o -

# every web ACL, not just the Firewall Manager ones
python fms_waf_report.py --profile my-profile --prefix '' -o all-web-acls.md

# progress to stderr while it walks the regions
python fms_waf_report.py --profile my-profile --verbose
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--profile` | credential chain | AWS named profile |
| `--regions` | `global,us-east-1,us-west-2,eu-central-1,eu-west-2` | comma-separated; `global` means scope CLOUDFRONT |
| `--days` | `7` | CloudWatch window |
| `--prefix` | `FMManagedWebACLV2-` | web ACL name prefix; `''` matches everything |
| `-o`, `--output` | `fms-waf-report.md` | output path, or `-` for stdout |
| `--verbose` | off | log progress to stderr |

## Partial results

A region that cannot be read does not abort the run. The failure is recorded as an
**Incomplete data** callout at the top of that region's section, naming the API and the error
code. Treat those sections as blind spots, not as clean results — an `AccessDenied` on
`ListMetrics` produces a rule table full of zeros that looks exactly like an idle web ACL.

`organizations` and `fms` are deliberately not called: from a member account
`fms:ListPolicies` returns nothing useful, and the policy name is already recoverable from
the web ACL name.

## Required IAM permissions

`SecurityAudit` or `ReadOnlyAccess` covers all of it. Minimal set:

```
sts:GetCallerIdentity
wafv2:ListWebACLs
wafv2:GetWebACL
wafv2:ListResourcesForWebACL
cloudfront:ListDistributions
cloudwatch:ListMetrics
cloudwatch:GetMetricData
```

## Before an organization migration

This is an inventory, not a readiness check — but it produces the artefact the migration
needs. Firewall Manager deletes the web ACLs it created when the account leaves the policy
scope, and leaving the organization *is* leaving the scope. Run this, keep the report, and
port the rule chain into your own Terraform **before** the account moves; otherwise you
rebuild it afterwards from sampled requests and memory.
