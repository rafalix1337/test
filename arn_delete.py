#!/usr/bin/env python3
"""
Delete AWS resources from a list of ARNs.

The core is generic: every deletion goes through the Cloud Control API
(cloudcontrol delete-resource), which covers ~1100 resource types with a
single call. The only per-type code is what's needed to derive
(TypeName, Identifier) from an ARN, plus an optional pre-hook for resources
that refuse to be deleted while protected or non-empty.

Nothing is deleted without --execute, and even then the full list of targets is
printed first followed by a countdown you can Ctrl-C out of (--grace).

Usage:
    python arn_delete.py arns.txt                      # dry run (default)
    python arn_delete.py arns.txt --check              # dry run + verify each resource exists
    python arn_delete.py arns.txt --execute            # print plan, wait 10s, then delete
    python arn_delete.py arns.txt --execute --grace 30 # longer window to abort
    python arn_delete.py arns.txt --execute --grace 0  # no countdown (unattended/CI)
    python arn_delete.py arns.txt --execute --force    # also strip deletion protection / empty buckets
    python arn_delete.py --arn arn:aws:... --execute
    python arn_delete.py arns.txt --role-arn arn:aws:iam::123:role/Deleter

Requires: boto3, and credentials allowed to delete the targets (Cloud Control
calls the underlying service APIs, so IAM must cover those actions).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from typing import Callable, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

# Anything the AWS SDK can raise for a call that failed for non-business reasons
# (bad region, no credentials, connection refused). Worth catching separately
# from ClientError so one flaky lookup cannot abort a whole run.
AWS_ERRORS = (ClientError, BotoCoreError)

# --------------------------------------------------------------------------- #
# ARN parsing
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Arn:
    raw: str
    partition: str
    service: str
    region: str
    account: str
    rest: str  # everything after the 5th colon
    rtype: str  # e.g. "instance", "log-group"; "" when the ARN carries no type
    rid: str  # whatever follows the type


def parse_arn(arn: str) -> Arn:
    parts = arn.strip().split(":", 5)
    if len(parts) != 6 or parts[0] != "arn":
        raise ValueError(f"not a valid ARN: {arn!r}")
    _, partition, service, region, account, rest = parts
    # API Gateway style: "arn:...::/restapis/abc" - the leading slash is not a separator
    rest = rest.lstrip("/")
    # The separator is whichever of "/" or ":" comes FIRST, otherwise
    # "log-group:/aws/lambda/x" would split into type "log-group:".
    cands = [rest.index(c) for c in "/:" if c in rest]
    if cands:
        i = min(cands)
        rtype, rid = rest[:i], rest[i + 1:]
    else:
        rtype, rid = "", rest
    return Arn(arn.strip(), partition, service, region, account, rest, rtype, rid)


# --------------------------------------------------------------------------- #
# Identifier extractors - Cloud Control expects different shapes per type
# --------------------------------------------------------------------------- #

ID = lambda a: a.rid  # noqa: E731  - whatever follows the resource type
FULL = lambda a: a.raw  # noqa: E731 - the whole ARN (ELBv2, SNS, Step Functions, ...)
LAST = lambda a: a.rid.rstrip("/").split("/")[-1]  # noqa: E731 - last segment (IAM with a path)


def LOG_GROUP(a: Arn) -> str:
    """Log group name, with the trailing ':*' that AWS appends stripped.
    Rejects log-STREAM ARNs, which would otherwise yield a garbage identifier."""
    if ":log-stream:" in a.rid:
        raise ValueError("log-stream ARNs are not deletable targets; "
                         "pass the log-group ARN if you mean the whole group")
    return a.rid[:-2] if a.rid.endswith(":*") else a.rid


def S3_BUCKET(a: Arn) -> str:
    """Bucket name. Refuses object ARNs - "bucket/key" must never be read as a
    bucket to delete, and Cloud Control has no AWS::S3::Object type anyway."""
    if "/" in a.rest:
        raise ValueError("S3 object/prefix ARNs are not deletable targets; "
                         "pass the bucket ARN if you mean the whole bucket")
    return a.rest


def SQS_URL(a: Arn) -> str:
    """SQS is identified by queue URL in Cloud Control, not by ARN."""
    return f"https://sqs.{a.region}.amazonaws.com/{a.account}/{a.rest}"


def SSM_NAME(a: Arn) -> str:
    """Hierarchical parameter names keep their leading slash; flat ones don't."""
    return f"/{a.rid}" if "/" in a.rid else a.rid


def ECS_SERVICE(a: Arn) -> str:
    """arn:aws:ecs:reg:acct:service/cluster/name -> "cluster|name" (composite key)."""
    return "|".join(a.rid.split("/")[-2:])


def EKS_NODEGROUP(a: Arn) -> str:
    """arn:aws:eks:reg:acct:nodegroup/cluster/ng/uuid -> "cluster|ng"."""
    return "|".join(a.rid.split("/")[:2])


# --------------------------------------------------------------------------- #
# Mapping: (service, resource-type) -> (TypeName, identifier extractor, order)
#
# order: lower is deleted first. Dependencies (SGs, subnets, VPCs, IAM) last.
# Adding a new type is one line. Full list of supported types:
#   aws cloudformation list-types --visibility PUBLIC --type RESOURCE
# --------------------------------------------------------------------------- #

MAPPING: dict[tuple[str, str], tuple[str, Callable[[Arn], str], int]] = {
    # --- compute ---------------------------------------------------------- #
    ("autoscaling", "autoScalingGroup"):        ("AWS::AutoScaling::AutoScalingGroup", LAST, 5),
    ("ec2", "instance"):                        ("AWS::EC2::Instance", ID, 10),
    ("lambda", "function"):                     ("AWS::Lambda::Function", ID, 10),
    ("ec2", "volume"):                          ("AWS::EC2::Volume", ID, 20),
    ("ec2", "snapshot"):                        ("AWS::EC2::Snapshot", ID, 20),
    ("ec2", "image"):                           ("AWS::EC2::Image", ID, 20),
    ("ec2", "network-interface"):               ("AWS::EC2::NetworkInterface", ID, 30),
    ("ec2", "natgateway"):                      ("AWS::EC2::NatGateway", ID, 40),
    ("ec2", "elastic-ip"):                      ("AWS::EC2::EIP", ID, 45),
    ("ec2", "security-group"):                  ("AWS::EC2::SecurityGroup", ID, 60),
    ("ec2", "subnet"):                          ("AWS::EC2::Subnet", ID, 70),
    ("ec2", "route-table"):                     ("AWS::EC2::RouteTable", ID, 70),
    ("ec2", "internet-gateway"):                ("AWS::EC2::InternetGateway", ID, 75),
    ("ec2", "vpc"):                             ("AWS::EC2::VPC", ID, 90),

    # --- containers ------------------------------------------------------- #
    ("ecs", "service"):                         ("AWS::ECS::Service", ECS_SERVICE, 10),
    ("eks", "nodegroup"):                       ("AWS::EKS::Nodegroup", EKS_NODEGROUP, 20),
    ("ecr", "repository"):                      ("AWS::ECR::Repository", ID, 20),
    ("ecs", "cluster"):                         ("AWS::ECS::Cluster", ID, 50),
    ("eks", "cluster"):                         ("AWS::EKS::Cluster", ID, 50),

    # --- databases -------------------------------------------------------- #
    ("rds", "db"):                              ("AWS::RDS::DBInstance", ID, 10),
    ("dynamodb", "table"):                      ("AWS::DynamoDB::Table", ID, 10),
    ("elasticache", "cluster"):                 ("AWS::ElastiCache::CacheCluster", ID, 10),
    ("elasticache", "replicationgroup"):        ("AWS::ElastiCache::ReplicationGroup", ID, 10),
    ("es", "domain"):                           ("AWS::OpenSearchService::Domain", LAST, 10),
    ("rds", "snapshot"):                        ("AWS::RDS::DBSnapshot", ID, 15),
    ("rds", "cluster"):                         ("AWS::RDS::DBCluster", ID, 20),
    ("rds", "subgrp"):                          ("AWS::RDS::DBSubnetGroup", ID, 60),

    # --- storage / messaging ---------------------------------------------- #
    ("sqs", ""):                                ("AWS::SQS::Queue", SQS_URL, 10),
    ("sns", ""):                                ("AWS::SNS::Topic", FULL, 10),
    ("kinesis", "stream"):                      ("AWS::Kinesis::Stream", ID, 10),
    ("s3", ""):                                 ("AWS::S3::Bucket", S3_BUCKET, 20),
    ("elasticfilesystem", "file-system"):       ("AWS::EFS::FileSystem", ID, 20),

    # --- networking / edge ------------------------------------------------ #
    ("elasticloadbalancing", "loadbalancer"):   ("AWS::ElasticLoadBalancingV2::LoadBalancer", FULL, 10),
    ("cloudfront", "distribution"):             ("AWS::CloudFront::Distribution", ID, 10),
    ("apigateway", "restapis"):                 ("AWS::ApiGateway::RestApi", LAST, 10),
    ("elasticloadbalancing", "targetgroup"):    ("AWS::ElasticLoadBalancingV2::TargetGroup", FULL, 20),
    ("route53", "hostedzone"):                  ("AWS::Route53::HostedZone", ID, 80),

    # --- IAM / observability / misc --------------------------------------- #
    ("cloudformation", "stack"):                ("AWS::CloudFormation::Stack", FULL, 1),
    ("cloudwatch", "alarm"):                    ("AWS::CloudWatch::Alarm", ID, 5),
    ("states", "stateMachine"):                 ("AWS::StepFunctions::StateMachine", FULL, 10),
    ("iam", "instance-profile"):                ("AWS::IAM::InstanceProfile", LAST, 75),
    ("iam", "role"):                            ("AWS::IAM::Role", LAST, 80),
    ("iam", "user"):                            ("AWS::IAM::User", LAST, 80),
    ("iam", "policy"):                          ("AWS::IAM::ManagedPolicy", FULL, 85),
    ("secretsmanager", "secret"):               ("AWS::SecretsManager::Secret", FULL, 90),
    ("ssm", "parameter"):                       ("AWS::SSM::Parameter", SSM_NAME, 90),
    ("logs", "log-group"):                      ("AWS::Logs::LogGroup", LOG_GROUP, 95),
}


@dataclass
class Target:
    arn: Arn
    type_name: str
    identifier: str
    order: int


def resolve(arn: Arn) -> Target:
    key = (arn.service, arn.rtype)
    if key not in MAPPING:
        # Some services (S3, SQS, SNS) carry no resource type in the ARN.
        key = (arn.service, "")
    if key not in MAPPING:
        raise KeyError(f"no mapping for service={arn.service!r} type={arn.rtype!r}")
    type_name, extractor, order = MAPPING[key]
    return Target(arn, type_name, extractor(arn), order)


def build_targets(arns: list[str]) -> tuple[list[Target], list[tuple[str, str]]]:
    """Resolve raw ARN strings into deletion targets, deduplicated and sorted
    leaf-first (see the `order` column in MAPPING)."""
    targets: list[Target] = []
    problems: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in arns:
        if item in seen:
            continue
        seen.add(item)
        try:
            targets.append(resolve(parse_arn(item)))
        except (ValueError, KeyError) as e:
            problems.append((item, str(e)))
    targets.sort(key=lambda t: t.order)
    return targets, problems


# --------------------------------------------------------------------------- #
# Pre-hooks: things Cloud Control will not do for you
# (deletion protection, non-empty containers). Only run with --force.
# --------------------------------------------------------------------------- #


class _AlreadyDone(Exception):
    """The pre-hook performed the full deletion; skip Cloud Control."""


def _hook_s3(t: Target, sess: boto3.Session, region: str) -> None:
    """S3 refuses to delete a non-empty bucket - drop objects and versions.
    Must use the bucket's own region or the calls hit PermanentRedirect."""
    bucket = sess.resource("s3", region_name=region).Bucket(t.identifier)
    bucket.object_versions.delete()
    bucket.objects.delete()


def _hook_rds_instance(t: Target, sess: boto3.Session, region: str) -> None:
    sess.client("rds", region_name=region).modify_db_instance(
        DBInstanceIdentifier=t.identifier,
        DeletionProtection=False,
        ApplyImmediately=True,
    )


def _hook_rds_cluster(t: Target, sess: boto3.Session, region: str) -> None:
    sess.client("rds", region_name=region).modify_db_cluster(
        DBClusterIdentifier=t.identifier,
        DeletionProtection=False,
        ApplyImmediately=True,
    )


def _hook_ec2_instance(t: Target, sess: boto3.Session, region: str) -> None:
    ec2 = sess.client("ec2", region_name=region)
    ec2.modify_instance_attribute(
        InstanceId=t.identifier, DisableApiTermination={"Value": False}
    )
    ec2.modify_instance_attribute(
        InstanceId=t.identifier, DisableApiStop={"Value": False}
    )


def _hook_ecr(t: Target, sess: boto3.Session, region: str) -> None:
    # Cloud Control has no "force" for a repo holding images - delete natively.
    sess.client("ecr", region_name=region).delete_repository(
        repositoryName=t.identifier, force=True
    )
    raise _AlreadyDone()


def _hook_elbv2(t: Target, sess: boto3.Session, region: str) -> None:
    sess.client("elbv2", region_name=region).modify_load_balancer_attributes(
        LoadBalancerArn=t.identifier,
        Attributes=[{"Key": "deletion_protection.enabled", "Value": "false"}],
    )


PRE_HOOKS: dict[str, Callable[[Target, boto3.Session, str], None]] = {
    "AWS::S3::Bucket": _hook_s3,
    "AWS::RDS::DBInstance": _hook_rds_instance,
    "AWS::RDS::DBCluster": _hook_rds_cluster,
    "AWS::EC2::Instance": _hook_ec2_instance,
    "AWS::ECR::Repository": _hook_ecr,
    "AWS::ElasticLoadBalancingV2::LoadBalancer": _hook_elbv2,
}


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #


class Deleter:
    def __init__(self, session: boto3.Session, role_arn: Optional[str] = None,
                 force: bool = False, timeout: int = 1800):
        self.session = session
        self.role_arn = role_arn
        self.force = force
        self.timeout = timeout
        self._clients: dict[str, object] = {}
        self._bucket_regions: dict[str, str] = {}

    def _cc(self, region: str):
        if region not in self._clients:
            self._clients[region] = self.session.client("cloudcontrol", region_name=region)
        return self._clients[region]

    def region_for(self, t: Target) -> str:
        """Region to call for this target.

        Most ARNs carry it. S3 and IAM ARNs don't: IAM is global so any region
        works, but an S3 bucket must be addressed in its own region, so look it
        up (cached) instead of guessing the session default.
        """
        if t.arn.region:
            return t.arn.region
        if t.type_name == "AWS::S3::Bucket":
            if t.identifier not in self._bucket_regions:
                try:
                    loc = self.session.client("s3").get_bucket_location(
                        Bucket=t.identifier
                    )["LocationConstraint"]
                    self._bucket_regions[t.identifier] = loc or "us-east-1"
                except AWS_ERRORS:
                    # Cached as "" so a failed lookup is not retried per call.
                    self._bucket_regions[t.identifier] = ""  # fall through below
            if self._bucket_regions[t.identifier]:
                return self._bucket_regions[t.identifier]
        return self.session.region_name or "us-east-1"

    # -- read-only ---------------------------------------------------------- #

    def exists(self, t: Target) -> tuple[bool, str]:
        """Read-only existence probe used by the dry run (--check)."""
        kwargs = {"TypeName": t.type_name, "Identifier": t.identifier}
        if self.role_arn:
            kwargs["RoleArn"] = self.role_arn
        try:
            self._cc(self.region_for(t)).get_resource(**kwargs)
            return True, "exists"
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "NotFoundException"):
                return False, "not found"
            return False, f"{code}: {e.response['Error']['Message']}"
        except BotoCoreError as e:
            # Bad region, no credentials, connection failure - report per target
            # instead of aborting the whole listing.
            return False, f"probe failed: {type(e).__name__}"

    # -- mutating ----------------------------------------------------------- #

    def delete(self, t: Target) -> tuple[str, str]:
        """Delete one target. Returns (status, message)."""
        region = self.region_for(t)

        if self.force and t.type_name in PRE_HOOKS:
            try:
                PRE_HOOKS[t.type_name](t, self.session, region)
            except _AlreadyDone:
                return "DELETED", "deleted natively by pre-hook"
            except ClientError as e:
                # e.g. no deletion protection to strip - keep going
                print(f"    pre-hook warning: {e.response['Error']['Code']}")

        kwargs = {"TypeName": t.type_name, "Identifier": t.identifier}
        if self.role_arn:
            kwargs["RoleArn"] = self.role_arn

        try:
            ev = self._cc(region).delete_resource(**kwargs)["ProgressEvent"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ResourceNotFoundException", "NotFoundException"):
                return "SKIPPED", "resource does not exist"
            if code == "UnsupportedActionException":
                return "UNSUPPORTED", f"{t.type_name} does not support DELETE via Cloud Control"
            return "ERROR", f"{code}: {e.response['Error']['Message']}"

        return self._wait(ev, region)

    def _wait(self, ev: dict, region: str) -> tuple[str, str]:
        token = ev["RequestToken"]
        deadline = time.time() + self.timeout
        delay = 3.0
        # CANCEL_IN_PROGRESS is also non-terminal - keep polling until it settles.
        while ev["OperationStatus"] in ("PENDING", "IN_PROGRESS", "CANCEL_IN_PROGRESS"):
            if time.time() > deadline:
                return "TIMEOUT", f"still in progress, token={token}"
            time.sleep(delay)
            delay = min(delay * 1.5, 30)
            ev = self._cc(region).get_resource_request_status(
                RequestToken=token
            )["ProgressEvent"]

        if ev["OperationStatus"] == "SUCCESS":
            return "DELETED", "ok"
        if ev.get("ErrorCode") in ("NotFound", "NotUpdatable"):
            return "SKIPPED", ev.get("StatusMessage", "does not exist")
        return "FAILED", f"{ev.get('ErrorCode')}: {ev.get('StatusMessage', '')}"


# --------------------------------------------------------------------------- #
# Dry run / execute
# --------------------------------------------------------------------------- #


def print_plan(targets: list[Target], problems: list[tuple[str, str]],
               header: str, deleter: Optional[Deleter] = None,
               probe: bool = False) -> int:
    """Print every target that would be touched.

    `deleter` is used only to resolve the real region per target (read-only).
    `probe` additionally calls GetResource per target to report existence, and
    is what makes this expensive - keep it off on the destructive path.

    Returns the number of targets that could not be found (0 unless probing).
    """
    print(f"\n{header}")
    print(f"{'ord':>4}  {'type':<44} {'account':<14} {'region':<15} identifier")
    print("-" * 100)
    missing = 0
    for t in targets:
        region = deleter.region_for(t) if deleter is not None else (t.arn.region or "?")
        line = (f"{t.order:>4}  {t.type_name:<44} {t.arn.account or '-':<14} "
                f"{region:<15} {t.identifier}")
        if probe and deleter is not None:
            ok, why = deleter.exists(t)
            if not ok:
                missing += 1
            line += f"   [{why}]"
        print(line)
    for item, why in problems:
        print(f"{'--':>4}  UNRECOGNIZED ARN: {item}  ({why})")
    return missing


def print_blast_radius(targets: list[Target], deleter: Optional[Deleter] = None) -> None:
    """Summarize which accounts and regions are about to be touched. Hitting more
    than one account is almost always a mistake worth stopping for."""
    accounts = sorted({t.arn.account for t in targets if t.arn.account})
    regions = sorted({(deleter.region_for(t) if deleter is not None else t.arn.region)
                      for t in targets if (deleter is not None or t.arn.region)})
    print(f"\n  accounts: {', '.join(accounts) or 'n/a'}")
    print(f"  regions:  {', '.join(regions) or 'n/a'}")
    if len(accounts) > 1:
        print(f"  *** WARNING: {len(accounts)} DIFFERENT ACCOUNTS in one run ***")


def dry_run(targets: list[Target], problems: list[tuple[str, str]],
            deleter: Optional[Deleter] = None) -> int:
    """Print the deletion plan without touching anything.

    Pass a Deleter to additionally probe each resource (read-only GetResource)
    and report whether it actually exists.
    """
    missing = print_plan(
        targets, problems,
        f"DRY RUN - {len(targets)} resource(s) planned, nothing will be deleted",
        deleter, probe=deleter is not None,
    )
    print_blast_radius(targets, deleter)
    print(f"\nplanned: {len(targets)}"
          + (f", unreachable/not found: {missing}" if deleter is not None else "")
          + f", unrecognized ARNs: {len(problems)}")
    print("Re-run with --execute to delete.")
    return 1 if problems else 0


def grace_period(seconds: int) -> bool:
    """Count down before destroying anything, so a wrong plan can be aborted
    with Ctrl-C. Returns False if the user interrupted."""
    try:
        for left in range(seconds, 0, -1):
            print(f"\r  Deleting in {left:>3}s ... press Ctrl-C to abort ",
                  end="", flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n  Aborted - nothing was deleted.")
        return False
    print("\r  Starting deletion.                                  ")
    return True


def execute(targets: list[Target], problems: list[tuple[str, str]],
            deleter: Deleter, grace: int = 10) -> int:
    # Always show what is about to be destroyed, then give a window to bail out.
    # probe=False: no GetResource storm on the destructive path, but regions are
    # still resolved so the list shows where each call will actually land.
    print_plan(targets, problems,
               f"ABOUT TO DELETE {len(targets)} resource(s) - THIS IS IRREVERSIBLE",
               deleter, probe=False)
    if not targets:
        print("\nNothing to delete.")
        return 1 if problems else 0
    print_blast_radius(targets, deleter)
    if problems:
        print(f"\n  note: {len(problems)} unrecognized ARN(s) above will be SKIPPED")
    print()
    if grace > 0 and not grace_period(grace):
        return 130

    results: list[tuple[Target, str, str]] = []
    print()
    for i, t in enumerate(targets, 1):
        print(f"[{i}/{len(targets)}] {t.type_name} {t.identifier} ... ", end="", flush=True)
        status, msg = deleter.delete(t)
        print(status if msg == "ok" else f"{status} ({msg})")
        results.append((t, status, msg))

    print("\n--- summary ---")
    bad = 0
    for t, status, msg in results:
        if status not in ("DELETED", "SKIPPED"):
            bad += 1
            print(f"  {status:<12} {t.arn.raw}  -> {msg}")
    ok = sum(1 for _, s, _ in results if s in ("DELETED", "SKIPPED"))
    print(f"  deleted/skipped: {ok}, failures: {bad}, unrecognized ARNs: {len(problems)}")
    return 0 if (bad == 0 and not problems) else 1


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


JSON_ARN_KEYS = ("ResourceARN", "Arn", "ARN", "arn")
JSON_LIST_KEYS = ("ResourceTagMappingList", "Resources", "arns", "Arns", "ARNs")


def arns_from_json(data: object) -> list[str]:
    """Pull ARNs out of common JSON shapes, so the output of AWS tooling can be
    piped straight in - notably `aws resourcegroupstaggingapi get-resources`,
    which returns {"ResourceTagMappingList": [{"ResourceARN": "..."}, ...]}.
    """
    if isinstance(data, dict):
        for key in JSON_LIST_KEYS:
            if key in data:
                return arns_from_json(data[key])
        raise ValueError(f"JSON object has none of {JSON_LIST_KEYS}")
    if not isinstance(data, list):
        raise ValueError("JSON must be a list of ARNs or an object containing one")

    out: list[str] = []
    for item in data:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict):
            for key in JSON_ARN_KEYS:
                if key in item:
                    out.append(item[key])
                    break
            else:
                raise ValueError(f"list item has none of {JSON_ARN_KEYS}: {item!r}")
        else:
            raise ValueError(f"cannot read an ARN from {item!r}")
    return out


def read_arns(path: Optional[str], inline: list[str]) -> list[str]:
    """Collect ARNs from inline --arn values plus a file.

    The file is either a flat list (one ARN per line, '#' starts a comment) or
    JSON - detected by the first non-whitespace character. Use '-' for stdin.
    """
    arns = list(inline)
    if path:
        if path == "-":
            text = sys.stdin.read()
        else:
            with open(path) as fh:
                text = fh.read()
        if text.lstrip().startswith(("[", "{")):
            arns += arns_from_json(json.loads(text))
        else:
            arns += [ln.split("#", 1)[0].strip() for ln in text.splitlines()]
    return [a.strip() for a in arns if a.strip()]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Delete AWS resources identified by ARN, generically via Cloud Control API."
    )
    p.add_argument("file", nargs="?",
                   help="flat file (one ARN per line, '#' starts a comment) or JSON "
                        "(list of ARNs, or AWS tooling output such as "
                        "resourcegroupstaggingapi get-resources); '-' reads stdin")
    p.add_argument("--arn", action="append", default=[], help="inline ARN (repeatable)")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--execute", action="store_true",
                      help="actually delete; without this the script only prints the plan")
    mode.add_argument("--dry-run", action="store_true",
                      help="explicitly force a dry run (the default when --execute is absent)")
    p.add_argument("--check", action="store_true",
                   help="during a dry run, probe each resource with a read-only GetResource call")
    p.add_argument("--force", action="store_true",
                   help="strip deletion protection and empty buckets/repos before deleting")
    p.add_argument("--grace", type=int, default=10, metavar="SECONDS",
                   help="countdown before deletion starts, to allow Ctrl-C (default 10; "
                        "0 disables it for unattended runs)")
    p.add_argument("--role-arn", help="IAM role passed to Cloud Control API")
    p.add_argument("--profile", help="AWS profile")
    p.add_argument("--region", help="fallback region for ARNs without one")
    p.add_argument("--timeout", type=int, default=1800,
                   help="max seconds to wait per resource (default 1800)")
    args = p.parse_args()

    try:
        arns = read_arns(args.file, args.arn)
    except OSError as e:
        p.error(f"cannot read {args.file}: {e.strerror}")
    except (json.JSONDecodeError, ValueError) as e:
        p.error(f"cannot parse {args.file}: {e}")
    if not arns:
        p.error("provide a file with ARNs or at least one --arn")

    targets, problems = build_targets(arns)

    if not args.execute:
        deleter = None
        if args.check:
            session = boto3.Session(profile_name=args.profile, region_name=args.region)
            deleter = Deleter(session, args.role_arn, args.force, args.timeout)
        return dry_run(targets, problems, deleter)

    session = boto3.Session(profile_name=args.profile, region_name=args.region)
    return execute(targets, problems,
                   Deleter(session, args.role_arn, args.force, args.timeout),
                   grace=max(0, args.grace))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Interrupted mid-deletion: earlier resources are already gone.
        print("\nInterrupted. Re-run to continue where it stopped.")
        sys.exit(130)
