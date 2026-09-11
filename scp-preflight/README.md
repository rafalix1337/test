# scp-preflight

Audits an AWS account before migrating it into an organization whose SCPs:

* **require IMDSv2** — `ec2:MetadataHttpTokens = required`
* **require EBS encryption** — `ec2:Encrypted = true`
* **forbid volume types** — `ec2:VolumeType` without `gp2` / `io1`

The script is **read-only**. It changes nothing — it prints ready-to-run remediation commands.

## Why this is needed

SCPs are preventive, not retroactive. Nothing breaks and nothing disappears at the moment
of migration — non-compliant resources keep running. The breakage lands on the first
`RunInstances` / `CreateVolume`: a redeploy, an ASG scale-out, an instance replacement
after an AZ failure. This script finds those landmines before you join the new org.

The one exception to "nothing breaks immediately": if the SCP includes an
`ec2:RoleDelivery` condition, every running instance with `HttpTokens=optional` that
actually uses IMDSv1 loses AWS API access the instant the account joins. Hence the
`instance` check.

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install boto3
```

Credentials come from the standard boto3 chain (`AWS_PROFILE`, `~/.aws/config`, SSO,
assumed roles). Required permissions: `ec2:Describe*`, `ec2:GetEbsEncryptionByDefault`,
`autoscaling:Describe*`, `sts:GetCallerIdentity` — `ReadOnlyAccess` covers it.

## Usage

```bash
# every enabled region
./scp_preflight.py --profile my-profile

# specific regions (faster)
./scp_preflight.py --profile my-profile --regions eu-west-1,eu-central-1

# if 'standard' is actually allowed by the SCP
./scp_preflight.py --blocked-types gp2,io1

# skip checks
./scp_preflight.py --skip instance,volume

# machine-readable output
./scp_preflight.py --json > preflight.json
```

| Flag | Meaning |
|---|---|
| `--profile` | AWS profile |
| `--regions` | comma-separated; defaults to every enabled region |
| `--blocked-types` | volume types forbidden by the SCP (default `gp2,io1,standard`) |
| `--skip` | checks to skip: `ebs-default,launch-template,launch-config,asg,instance,volume` |
| `--json` | JSON instead of the text report |
| `--exit-zero` | always exit 0 |

**Exit codes:** `0` — no findings · `1` — findings present · `2` — no usable credentials.
Suitable as a CI gate in front of the migration.

## What it checks

| Check | Detects |
|---|---|
| `ebs-default` | *EBS encryption by default* disabled (a per-account, per-region setting) |
| `launch-template` | `$Default` and `$Latest` versions: `HttpTokens != required`, forbidden type in BDM, `Encrypted != true` |
| `launch-config` | the same in launch configurations (legacy) |
| `asg` | ASGs pinned to a **numeric** LT version, or still on a launch configuration |
| `instance` | running/stopped instances with `HttpTokens != required` |
| `volume` | existing volumes of a forbidden type, with a ready `modify-volume` command |

The `asg` check exists because **fixing the LT alone does nothing**:
`modify-launch-template` creates a new version, and an ASG pinned to `Version: "5"` keeps
launching the old one.

## What it deliberately does NOT check

* **Self-owned AMIs** — golden AMI assumption: images are built centrally with compliant
  settings. That is why a launch template with **no** `BlockDeviceMappings` is not flagged
  for volume type (it inherits from the AMI). If the golden AMI stops being a guarantee,
  add a `describe-images --owners self` check.
* **Snapshots and unencrypted volumes on the restore path** — accepted risk: the SCP will
  be relaxed temporarily if a restore is ever needed. Note that this is an action in the
  *destination* org's management account, so your RTO starts depending on another team's
  response time. Worth writing into the runbook with an escalation contact.
* **IMDS hop limit** (`ec2:MetadataHttpPutResponseHopLimit`) — out of scope. If the target
  SCP forced `1`, containers on Docker bridge networking would lose IMDS access; that is
  an architectural problem, not a configuration one.
* **Managed services** — e.g. `io1` storage in RDS is not subject to `ec2:VolumeType`,
  because RDS does not call `ec2:CreateVolume` in your account.

## Remediation order

1. `enable-ebs-encryption-by-default` in every region — cheapest fix, widest effect.
2. `modify-volume` gp2→gp3, io1→io2 — **online, no detach**, and gp3 is cheaper too.
3. Launch templates: new version with `HttpTokens=required` and gp3 in the BDM.
4. ASGs: point at `$Latest` (or bump the default version), then `start-instance-refresh`.
5. Launch configurations: rewrite as launch templates — LCs are immutable.
6. Instances: `modify-instance-metadata-options` — **but read the next section first**.

### Before flipping instances to `required`

The script shows who **can** use IMDSv1. Check who **actually** does — the per-instance
CloudWatch metric `MetadataNoToken`. Flipping to `required` without that is a direct route
to an outage: old SDKs (AWS SDK for Java v1 < 1.11.678, old boto, old kube2iam,
CloudWatch Agent, SSM Agent < 2.3.x) cannot do v2.

A shortcut that covers new instances without touching any launch template:

```bash
aws ec2 modify-instance-metadata-defaults --region eu-west-1 \
  --http-tokens required --http-put-response-hop-limit 2 --http-endpoint enabled
```

## After the migration

Watch CloudTrail for `errorCode = AccessDenied` for the first few weeks — SCP denials
surface there, and it is the only way to catch the paths nobody thought of.

One detail not to build a plan on: **SCPs do not apply to service-linked roles**, so some
ASG launches will technically slip through. The launch template still decides the volume
type, and the behaviour is ambiguous — treat it as trivia, not as a workaround.
