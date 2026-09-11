#!/usr/bin/env python3
"""
scp_preflight.py — audit an AWS account before migrating it into an organization
whose SCPs:
  * require IMDSv2          (ec2:MetadataHttpTokens = required)
  * require EBS encryption  (ec2:Encrypted = true)
  * forbid volume types gp2 / io1  (ec2:VolumeType)

Read-only. Exits 1 when findings exist, so it works as a CI gate.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import sys
from dataclasses import dataclass, field, asdict

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:
    sys.exit("boto3 is missing. Install it with:  python3 -m pip install boto3")

DEFAULT_BLOCKED = ("gp2", "io1", "standard")
# what each forbidden type should be converted to
REPLACEMENT = {"gp2": "gp3", "standard": "gp3", "io1": "io2", "sc1": "st1"}

HIGH, MED = "HIGH", "MED"


@dataclass
class Finding:
    region: str
    category: str
    resource: str
    severity: str
    issues: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────── helpers ──
def _cli_flags(profile: str | None, region: str) -> str:
    return (f" --profile {profile}" if profile else "") + f" --region {region}"


def _paginate(client, op: str, key: str, **kwargs):
    """Yield items from a paginator, falling back to a single call."""
    if client.can_paginate(op):
        for page in client.get_paginator(op).paginate(**kwargs):
            yield from page.get(key, [])
    else:
        yield from getattr(client, op)(**kwargs).get(key, [])


def _bdm_issues(bdms: list[dict], blocked: set[str]) -> list[str]:
    """Problems in BlockDeviceMappings. No BDM at all => inherited from the AMI."""
    out = []
    for bdm in bdms or []:
        ebs = bdm.get("Ebs")
        if not ebs:
            continue
        dev = bdm.get("DeviceName", "?")
        vtype = ebs.get("VolumeType")
        if vtype and vtype in blocked:
            out.append(f"{dev}: volume type {vtype} (forbidden)")
        # skip the Encrypted check when the volume comes from a snapshot —
        # it inherits encryption from that snapshot
        if not ebs.get("Encrypted") and not ebs.get("SnapshotId"):
            out.append(f"{dev}: Encrypted is not set to true")
    return out


# ──────────────────────────────────────────────────────────────────── checks ──
def check_ebs_default(ec2, region, profile) -> list[Finding]:
    if ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        return []
    return [Finding(region, "ebs-default", f"region {region}", HIGH,
                    ["EBS encryption by default is DISABLED"],
                    [f"aws ec2 enable-ebs-encryption-by-default{_cli_flags(profile, region)}"])]


def check_launch_templates(ec2, region, profile, blocked) -> list[Finding]:
    findings = []
    for lt in _paginate(ec2, "describe_launch_templates", "LaunchTemplates"):
        lt_id = lt["LaunchTemplateId"]
        try:
            versions = ec2.describe_launch_template_versions(
                LaunchTemplateId=lt_id, Versions=["$Default", "$Latest"]
            )["LaunchTemplateVersions"]
        except ClientError as e:
            findings.append(Finding(region, "launch-template", lt_id, MED,
                                    [f"could not read versions: {e.response['Error']['Code']}"]))
            continue

        for v in {ver["VersionNumber"]: ver for ver in versions}.values():  # dedupe
            data = v.get("LaunchTemplateData", {})
            issues = []

            tokens = data.get("MetadataOptions", {}).get("HttpTokens")
            if tokens != "required":
                issues.append(f"IMDSv2 not enforced (HttpTokens={tokens or 'unset'})")

            issues += _bdm_issues(data.get("BlockDeviceMappings"), blocked)
            if not issues:
                continue

            tag = " [default]" if v.get("DefaultVersion") else ""
            findings.append(Finding(
                region, "launch-template",
                f"{v['LaunchTemplateName']} v{v['VersionNumber']}{tag}", HIGH, issues,
                [f"create a fixed version, point the ASG at $Latest, "
                 f"then run start-instance-refresh (LT ID: {lt_id})"],
            ))
    return findings


def check_launch_configs(asg, region, profile, blocked) -> list[Finding]:
    findings = []
    for lc in _paginate(asg, "describe_launch_configurations", "LaunchConfigurations"):
        issues = []
        tokens = lc.get("MetadataOptions", {}).get("HttpTokens")
        if tokens != "required":
            issues.append(f"IMDSv2 not enforced (HttpTokens={tokens or 'unset'})")
        issues += _bdm_issues(lc.get("BlockDeviceMappings"), blocked)
        if issues:
            findings.append(Finding(
                region, "launch-config", lc["LaunchConfigurationName"], HIGH, issues,
                ["launch configurations are immutable — migrate the ASG to a launch template"],
            ))
    return findings


def check_asgs(asg, region, profile) -> list[Finding]:
    """ASGs pinned to a numeric LT version will not pick up the fixed version."""
    findings = []
    for g in _paginate(asg, "describe_auto_scaling_groups", "AutoScalingGroups"):
        name = g["AutoScalingGroupName"]
        if g.get("LaunchConfigurationName"):
            findings.append(Finding(
                region, "asg", name, HIGH,
                [f"still uses a launch configuration: {g['LaunchConfigurationName']}"],
                ["migrate to a launch template"]))
            continue

        spec = g.get("LaunchTemplate") or (
            g.get("MixedInstancesPolicy", {})
             .get("LaunchTemplate", {})
             .get("LaunchTemplateSpecification", {}))
        ver = str(spec.get("Version", ""))
        if ver.isdigit():
            findings.append(Finding(
                region, "asg", name, MED,
                [f"pinned to {spec.get('LaunchTemplateName', '?')} v{ver} "
                 f"— a new LT version will NOT be picked up"],
                [f"aws autoscaling update-auto-scaling-group{_cli_flags(profile, region)} "
                 f"--auto-scaling-group-name {name} "
                 f"--launch-template LaunchTemplateName={spec.get('LaunchTemplateName','?')},Version='$Latest'"]))
    return findings


def check_instances(ec2, region, profile) -> list[Finding]:
    findings = []
    pages = _paginate(ec2, "describe_instances", "Reservations",
                      Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}])
    for res in pages:
        for inst in res.get("Instances", []):
            mo = inst.get("MetadataOptions", {})
            if mo.get("HttpEndpoint") == "disabled":
                continue  # IMDS off entirely — the SCP does not apply
            if mo.get("HttpTokens") == "required":
                continue
            iid = inst["InstanceId"]
            name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), "-")
            findings.append(Finding(
                region, "instance", f"{iid} ({name})", HIGH,
                [f"HttpTokens={mo.get('HttpTokens') or 'unset'} "
                 f"— under an SCP with ec2:RoleDelivery this loses AWS API access immediately"],
                [f"aws ec2 modify-instance-metadata-options{_cli_flags(profile, region)} "
                 f"--instance-id {iid} --http-tokens required --http-endpoint enabled"]))
    return findings


def check_volumes(ec2, region, profile, blocked) -> list[Finding]:
    findings = []
    vols = _paginate(ec2, "describe_volumes", "Volumes",
                     Filters=[{"Name": "volume-type", "Values": sorted(blocked)}])
    for v in vols:
        vid, vtype = v["VolumeId"], v["VolumeType"]
        target = REPLACEMENT.get(vtype, "gp3")
        cmd = (f"aws ec2 modify-volume{_cli_flags(profile, region)} "
               f"--volume-id {vid} --volume-type {target}")
        if target == "io2":
            cmd += f" --iops {v.get('Iops', 3000)}"
        attached = ", ".join(a["InstanceId"] for a in v.get("Attachments", [])) or "detached"
        issues = [f"type {vtype} ({v['Size']} GiB, {attached})"]
        if not v.get("Encrypted"):
            issues.append("UNENCRYPTED")
        findings.append(Finding(region, "volume", vid, MED, issues, [cmd]))
    return findings


# ───────────────────────────────────────────────────────────────────── driver ──
def scan_region(region, profile, blocked, skip) -> list[Finding]:
    session = boto3.Session(profile_name=profile, region_name=region)  # one per thread
    ec2, asg = session.client("ec2"), session.client("autoscaling")
    out: list[Finding] = []
    checks = [
        ("ebs-default",     lambda: check_ebs_default(ec2, region, profile)),
        ("launch-template", lambda: check_launch_templates(ec2, region, profile, blocked)),
        ("launch-config",   lambda: check_launch_configs(asg, region, profile, blocked)),
        ("asg",             lambda: check_asgs(asg, region, profile)),
        ("instance",        lambda: check_instances(ec2, region, profile)),
        ("volume",          lambda: check_volumes(ec2, region, profile, blocked)),
    ]
    for name, fn in checks:
        if name in skip:
            continue
        try:
            out += fn()
        except (ClientError, BotoCoreError) as e:
            out.append(Finding(region, name, "-", MED, [f"check failed: {e}"]))
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--profile", help="AWS profile")
    p.add_argument("--regions", help="comma-separated; defaults to every enabled region")
    p.add_argument("--blocked-types", default=",".join(DEFAULT_BLOCKED),
                   help=f"volume types forbidden by the SCP (default: {','.join(DEFAULT_BLOCKED)})")
    p.add_argument("--skip", default="", help="checks to skip, e.g. instance,volume")
    p.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    p.add_argument("--exit-zero", action="store_true", help="always exit 0")
    args = p.parse_args()

    blocked = {t.strip() for t in args.blocked_types.split(",") if t.strip()}
    skip = {s.strip() for s in args.skip.split(",") if s.strip()}

    try:
        base = boto3.Session(profile_name=args.profile)
        account = base.client("sts").get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as e:
        return print(f"No usable AWS credentials: {e}", file=sys.stderr) or 2

    regions = ([r.strip() for r in args.regions.split(",")] if args.regions
               else [r["RegionName"] for r in
                     base.client("ec2", region_name="us-east-1").describe_regions()["Regions"]])

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = pool.map(lambda r: scan_region(r, args.profile, blocked, skip), regions)
        findings = [f for chunk in results for f in chunk]

    if args.json:
        print(json.dumps({"account": account, "regions": regions,
                          "blocked_types": sorted(blocked),
                          "findings": [asdict(f) for f in findings]}, indent=2))
    else:
        color = sys.stdout.isatty()
        bold = (lambda s: f"\033[1m{s}\033[0m") if color else (lambda s: s)
        red = (lambda s: f"\033[31m{s}\033[0m") if color else (lambda s: s)
        green = (lambda s: f"\033[32m{s}\033[0m") if color else (lambda s: s)

        print(f"{bold('Account')}: {account}   {bold('Forbidden types')}: {', '.join(sorted(blocked))}")
        print(f"{bold('Regions')}: {len(regions)} scanned")

        for region in regions:
            rf = [f for f in findings if f.region == region]
            if not rf:
                continue
            print(f"\n{bold('══ ' + region + ' ══')}")
            for cat in dict.fromkeys(f.category for f in rf):
                print(f"\n  {bold(cat)}")
                for f in (x for x in rf if x.category == cat):
                    print(f"    {red('✗')} [{f.severity}] {f.resource}")
                    for i in f.issues:
                        print(f"        {i}")
                    for r in f.remediation:
                        print(f"        → {r}")

        print(f"\n{bold('═══ SUMMARY ═══')}")
        if not findings:
            print(green("No blockers — the account is ready for the new organization's SCPs."))
        else:
            high = sum(1 for f in findings if f.severity == HIGH)
            print(red(f"{len(findings)} finding(s) ({high} HIGH) to fix before migrating."))

    return 0 if (args.exit_zero or not findings) else 1


if __name__ == "__main__":
    sys.exit(main())
