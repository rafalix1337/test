#!/usr/bin/env python3
"""Read-only audit of AWS Systems Manager configuration that MUST be addressed
before moving an account to a different AWS Organization.

Reporting rule: a finding is emitted only when the script has read the actual
resource and can point at the evidence. No naming-convention guesses, no "you
might want to check X". Anything the script could not read is reported as
UNCHECKED - a blind spot, never as a pass.

SSM documents themselves survive the move untouched: they are account-scoped and
the account ID does not change. What breaks is configuration pinned to the
organization, which is what this audits.

Only Describe/Get/List calls. Nothing is mutated.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except ImportError:  # pragma: no cover
    sys.exit("boto3 is required: pip install boto3")


ORG_ID_RE = re.compile(r"\bo-[a-z0-9]{10,32}\b")
OU_ID_RE = re.compile(r"\bou-[a-z0-9]{4,32}-[a-z0-9]{8,32}\b")
ORG_CONDITION_KEYS = (
    "aws:PrincipalOrgID",
    "aws:PrincipalOrgPaths",
    "aws:ResourceOrgID",
    "aws:ResourceOrgPaths",
)

SSM_ENDPOINT_SUFFIXES = (".ssm", ".ssmmessages", ".ec2messages")

MUST_FIX = "MUST-FIX"
UNCHECKED = "UNCHECKED"
SEVERITY_ORDER = {MUST_FIX: 0, UNCHECKED: 1}


@dataclass
class Finding:
    severity: str
    check: str
    region: str
    resource: str
    evidence: str
    action: str


def org_references(blob: Any) -> list[str]:
    """Return the concrete tokens that tie `blob` to the current organization."""
    text = blob if isinstance(blob, str) else json.dumps(blob)
    reasons: list[str] = []
    for key in ORG_CONDITION_KEYS:
        if key in text:
            reasons.append(key)
    for org_id in sorted(set(ORG_ID_RE.findall(text))):
        reasons.append(org_id)
    for ou_id in sorted(set(OU_ID_RE.findall(text))):
        reasons.append(ou_id)
    return reasons


class Auditor:
    def __init__(self, session: boto3.Session, region: str, verbose: bool) -> None:
        self.session = session
        self.region = region
        self.verbose = verbose
        self.findings: list[Finding] = []
        self._clients: dict[str, Any] = {}
        self._seen_targets: set[str] = set()
        self.account_id = ""
        self.org_id = ""
        self.document_count = 0

    # -- plumbing ---------------------------------------------------------

    def client(self, name: str):
        if name not in self._clients:
            self._clients[name] = self.session.client(name, region_name=self.region)
        return self._clients[name]

    def add(self, severity: str, check: str, resource: str, evidence: str, action: str) -> None:
        self.findings.append(Finding(severity, check, self.region, resource, evidence, action))

    def unchecked(self, check: str, resource: str, err: Exception) -> None:
        code = ""
        if isinstance(err, ClientError):
            code = err.response.get("Error", {}).get("Code", "")
        self.add(
            UNCHECKED,
            check,
            resource,
            f"{code or type(err).__name__}: {err}",
            "re-run with credentials that allow this call - this is a blind spot, "
            "not a pass",
        )

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"  .. {message}", file=sys.stderr)

    def paginate(self, client_name: str, operation: str, key: str, **kwargs) -> Iterable[dict]:
        paginator = self.client(client_name).get_paginator(operation)
        for page in paginator.paginate(**kwargs):
            yield from page.get(key, [])

    def load_context(self) -> None:
        try:
            self.account_id = self.client("sts").get_caller_identity()["Account"]
        except (ClientError, BotoCoreError) as err:
            raise SystemExit(f"cannot resolve caller identity in {self.region}: {err}")
        try:
            self.org_id = self.client("organizations").describe_organization()["Organization"]["Id"]
        except (ClientError, BotoCoreError):
            self.org_id = ""  # header metadata only, not a check

    # -- shared policy inspection -----------------------------------------

    def check_bucket_policy(self, bucket: str, used_for: str) -> None:
        if f"s3:{bucket}" in self._seen_targets:
            return
        self._seen_targets.add(f"s3:{bucket}")
        try:
            policy = self.client("s3").get_bucket_policy(Bucket=bucket)["Policy"]
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") == "NoSuchBucketPolicy":
                return  # no policy means no org condition - a real pass
            self.unchecked("bucket-policy", f"s3://{bucket}", err)
            return
        except BotoCoreError as err:
            self.unchecked("bucket-policy", f"s3://{bucket}", err)
            return

        reasons = org_references(policy)
        if reasons:
            self.add(
                MUST_FIX,
                "bucket-policy",
                f"s3://{bucket}",
                f"{used_for}; bucket policy contains {', '.join(reasons)}",
                "this account's principals stop matching the condition once the org id "
                "changes - grant the account explicitly, or update the condition to the "
                "target organization",
            )

    def check_key_policy(self, key_id: str, used_for: str) -> None:
        if key_id.startswith("alias/aws/"):
            return  # AWS-managed key, no customer policy to break
        if f"kms:{key_id}" in self._seen_targets:
            return
        self._seen_targets.add(f"kms:{key_id}")
        try:
            policy = self.client("kms").get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
        except (ClientError, BotoCoreError) as err:
            self.unchecked("kms-key-policy", f"kms/{key_id}", err)
            return

        reasons = org_references(policy)
        if reasons:
            self.add(
                MUST_FIX,
                "kms-key-policy",
                f"kms/{key_id}",
                f"{used_for}; key policy contains {', '.join(reasons)}",
                "kms:Decrypt/GenerateDataKey from this account starts returning "
                "AccessDenied once the org id changes - grant the account explicitly, "
                "or update the condition to the target organization",
            )

    # -- checks -----------------------------------------------------------

    def check_document_content(self) -> None:
        """Self-owned documents whose body hardcodes the current org or its OUs."""
        try:
            docs = list(
                self.paginate(
                    "ssm",
                    "list_documents",
                    "DocumentIdentifiers",
                    Filters=[{"Key": "Owner", "Values": ["Self"]}],
                )
            )
        except (ClientError, BotoCoreError) as err:
            self.unchecked("document-content", "documents owned by this account", err)
            return

        self.document_count = len(docs)
        ssm = self.client("ssm")
        for doc in docs:
            name = doc["Name"]
            self.log(f"document {name}")
            try:
                content = ssm.get_document(Name=name)["Content"]
            except (ClientError, BotoCoreError) as err:
                self.unchecked("document-content", f"document/{name}", err)
                continue
            reasons = org_references(content)
            if reasons:
                self.add(
                    MUST_FIX,
                    "document-content",
                    f"document/{name}",
                    "document body contains " + ", ".join(reasons),
                    "the document resolves against the current organization - rewrite it "
                    "for the target organization before it is next executed",
                )

    def check_resource_data_syncs(self) -> None:
        """Org-sourced syncs, and the destinations every sync actually writes to."""
        for sync_type in ("SyncToDestination", "SyncFromSource"):
            try:
                syncs = list(
                    self.paginate(
                        "ssm",
                        "list_resource_data_sync",
                        "ResourceDataSyncItems",
                        SyncType=sync_type,
                    )
                )
            except (ClientError, BotoCoreError) as err:
                self.unchecked("resource-data-sync", f"syncs of type {sync_type}", err)
                continue

            for sync in syncs:
                name = sync.get("SyncName", "?")
                source = sync.get("SyncSource") or {}
                if source.get("SourceType") == "AwsOrganizations":
                    org_source = source.get("AwsOrganizationsSource", {}) or {}
                    detail = "SyncSource.SourceType is AwsOrganizations"
                    if org_source.get("OrganizationSourceType"):
                        detail += f" ({org_source['OrganizationSourceType']})"
                    if org_source.get("OrganizationalUnits"):
                        units = [
                            u.get("OrganizationalUnitId", "")
                            for u in org_source["OrganizationalUnits"]
                        ]
                        detail += " over " + ", ".join(filter(None, units))
                    self.add(
                        MUST_FIX,
                        "resource-data-sync",
                        f"resource-data-sync/{name}",
                        detail,
                        "the sync is bound to the current organization and stops "
                        "aggregating on the move - delete and recreate it against the "
                        "target organization",
                    )

                destination = sync.get("S3Destination") or {}
                if destination.get("BucketName"):
                    self.check_bucket_policy(
                        destination["BucketName"], f"Resource Data Sync '{name}' destination"
                    )
                if destination.get("AWSKMSKeyARN"):
                    self.check_key_policy(
                        destination["AWSKMSKeyARN"], f"Resource Data Sync '{name}' destination"
                    )

    def check_delegated_administrator(self) -> None:
        """Only matters if THIS account is the SSM delegated admin."""
        try:
            admins = list(
                self.paginate(
                    "organizations",
                    "list_delegated_administrators",
                    "DelegatedAdministrators",
                    ServicePrincipal="ssm.amazonaws.com",
                )
            )
        except (ClientError, BotoCoreError) as err:
            self.unchecked(
                "delegated-administrator", "ssm.amazonaws.com delegated admin", err
            )
            return

        for admin in admins:
            if admin["Id"] != self.account_id:
                continue  # someone else's problem
            self.add(
                MUST_FIX,
                "delegated-administrator",
                f"account/{admin['Id']}",
                "this account is the delegated administrator for ssm.amazonaws.com "
                f"in {self.org_id or 'the current organization'}",
                "the registration is lost on the move - hand the role to another "
                "account before migrating, and register a delegated admin in the "
                "target organization",
            )

    def check_vpc_endpoints(self) -> None:
        """Policies on the SSM data-plane endpoints, matched by service name."""
        try:
            endpoints = list(
                self.paginate(
                    "ec2",
                    "describe_vpc_endpoints",
                    "VpcEndpoints",
                    Filters=[{"Name": "vpc-endpoint-type", "Values": ["Interface"]}],
                )
            )
        except (ClientError, BotoCoreError) as err:
            self.unchecked("vpc-endpoint-policy", "ssm/ssmmessages/ec2messages endpoints", err)
            return

        for endpoint in endpoints:
            service = endpoint.get("ServiceName", "")
            if not service.endswith(SSM_ENDPOINT_SUFFIXES):
                continue
            reasons = org_references(endpoint.get("PolicyDocument") or "")
            if reasons:
                self.add(
                    MUST_FIX,
                    "vpc-endpoint-policy",
                    f"{endpoint['VpcEndpointId']} ({service})",
                    "endpoint policy contains " + ", ".join(reasons),
                    "SSM Agent and Session Manager traffic from this account is denied "
                    "once the org id changes - update the policy to the target "
                    "organization before migrating",
                )

    def check_session_manager_targets(self) -> None:
        """Log bucket and CMK configured in SSM-SessionManagerRunShell."""
        try:
            content = self.client("ssm").get_document(Name="SSM-SessionManagerRunShell")["Content"]
            inputs = json.loads(content).get("inputs", {})
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") == "InvalidDocument":
                return  # preferences never customised - nothing configured to break
            self.unchecked("session-manager", "SSM-SessionManagerRunShell", err)
            return
        except (BotoCoreError, ValueError) as err:
            self.unchecked("session-manager", "SSM-SessionManagerRunShell", err)
            return

        if inputs.get("s3BucketName"):
            self.check_bucket_policy(inputs["s3BucketName"], "Session Manager session logs")
        if inputs.get("kmsKeyId"):
            self.check_key_policy(inputs["kmsKeyId"], "Session Manager session encryption")

    def check_securestring_keys(self) -> None:
        """CMKs behind SecureString parameters - the deferred-failure path.

        Nothing breaks at migration time; the next GetParameter WithDecryption
        after a restart or scale-out does.
        """
        try:
            params = list(self.paginate("ssm", "describe_parameters", "Parameters"))
        except (ClientError, BotoCoreError) as err:
            self.unchecked("securestring-key", "SecureString parameters", err)
            return

        keys: dict[str, list[str]] = {}
        for param in params:
            if param.get("Type") != "SecureString":
                continue
            key_id = param.get("KeyId", "")
            if not key_id or key_id.startswith("alias/aws/"):
                continue  # AWS-managed key, no customer policy to break
            keys.setdefault(key_id, []).append(param["Name"])

        for key_id, names in keys.items():
            self.log(f"securestring key {key_id} ({len(names)} parameter(s))")
            sample = ", ".join(sorted(names)[:3])
            if len(names) > 3:
                sample += f", +{len(names) - 3} more"
            self.check_key_policy(
                key_id, f"{len(names)} SecureString parameter(s) ({sample})"
            )

    # -- driver -----------------------------------------------------------

    def run(self) -> list[Finding]:
        self.load_context()
        for check in (
            self.check_document_content,
            self.check_resource_data_syncs,
            self.check_delegated_administrator,
            self.check_vpc_endpoints,
            self.check_session_manager_targets,
            self.check_securestring_keys,
        ):
            self.log(f"running {check.__name__}")
            try:
                check()
            except (ClientError, BotoCoreError) as err:  # defensive
                self.unchecked(check.__name__, "-", err)
        return self.findings


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(
    findings: list[Finding], meta: dict[str, str], regions: list[str] | None = None
) -> str:
    """One section per region, listing what has to be fixed there."""
    if regions is None:
        regions = list(dict.fromkeys(f.region for f in findings))

    must_fix = [f for f in findings if f.severity == MUST_FIX]

    out: list[str] = []
    out.append("# SSM organization-migration readiness report")
    out.append("")
    out.append(
        "Every item below was read from the live resource named in it, and every one "
        "of them has to be resolved before this account changes organization."
    )
    out.append("")

    out.append("## Scope")
    out.append("")
    out.append("| Field | Value |")
    out.append("| --- | --- |")
    for label, key in (
        ("Generated (UTC)", "generated_at"),
        ("Account", "account_id"),
        ("Current organization", "org_id"),
        ("Profile", "profile"),
        ("Regions", "regions"),
        ("SSM documents owned", "document_count"),
        ("Items to fix", "-"),
    ):
        value = str(len(must_fix)) if key == "-" else meta.get(key) or "-"
        out.append(f"| {label} | {md_escape(value)} |")
    out.append("")

    for region in regions:
        out.append(f"## {region}")
        out.append("")
        region_fixes = [f for f in must_fix if f.region == region]
        region_unchecked = [
            f for f in findings if f.region == region and f.severity == UNCHECKED
        ]

        if region_fixes:
            out.append("| Resource | What is wrong | Fix |")
            out.append("| --- | --- | --- |")
            for f in region_fixes:
                out.append(
                    f"| `{md_escape(f.resource)}` | {md_escape(f.evidence)} "
                    f"| {md_escape(f.action)} |"
                )
            out.append("")
        elif not region_unchecked:
            out.append("Nothing to fix.")
            out.append("")
        else:
            out.append("Nothing to fix in what could be read.")
            out.append("")

        if region_unchecked:
            out.append("### Could not be read")
            out.append("")
            out.append("| Resource | Error |")
            out.append("| --- | --- |")
            for f in region_unchecked:
                out.append(f"| `{md_escape(f.resource)}` | {md_escape(f.evidence)} |")
            out.append("")

    return "\n".join(out)


def render(findings: list[Finding], as_json: bool) -> None:
    if as_json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
        return

    if not findings:
        print("nothing to fix: every check ran and came back clean")
        return

    must_fix = [f for f in findings if f.severity == MUST_FIX]
    for region in dict.fromkeys(f.region for f in findings):
        print(f"\n=== {region} ===")
        region_fixes = [f for f in must_fix if f.region == region]
        if not region_fixes:
            print("nothing to fix")
        for finding in region_fixes:
            print(f"{finding.check}: {finding.resource}")
            print(f"    wrong: {finding.evidence}")
            print(f"    fix:   {finding.action}")
        for finding in [f for f in findings if f.region == region and f.severity == UNCHECKED]:
            print(f"could not read {finding.resource}: {finding.evidence}")

    print(f"\n{len(must_fix)} item(s) to fix before the migration")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit SSM configuration that must be fixed before an AWS account "
        "moves to a different AWS Organization (read-only, evidence-based).",
    )
    parser.add_argument("--profile", help="AWS named profile (default: credential chain)")
    parser.add_argument(
        "--region",
        help="Region, or comma-separated regions (default: the profile's region)",
    )
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument(
        "--markdown",
        nargs="?",
        const="ssm-migration-report.md",
        metavar="PATH",
        help="also write a Markdown report (default: ssm-migration-report.md; "
        "'-' prints it to stdout instead of the text report)",
    )
    parser.add_argument("--verbose", action="store_true", help="log progress to stderr")
    parser.add_argument(
        "--fail-on",
        choices=["must-fix", "unchecked", "never"],
        default="must-fix",
        help="exit non-zero on findings at this level or worse (default: must-fix)",
    )
    args = parser.parse_args()

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    except BotoCoreError as err:
        raise SystemExit(str(err))

    if args.region:
        regions = [r.strip() for r in args.region.split(",") if r.strip()]
    elif session.region_name:
        regions = [session.region_name]
    else:
        raise SystemExit("no region: pass --region or configure the profile")

    findings: list[Finding] = []
    auditors: list[Auditor] = []
    for region in regions:
        if args.verbose:
            print(f"auditing {region}", file=sys.stderr)
        auditor = Auditor(session, region, args.verbose)
        findings.extend(auditor.run())
        auditors.append(auditor)

    if args.markdown:
        meta = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
            "account_id": next((a.account_id for a in auditors if a.account_id), ""),
            "org_id": next((a.org_id for a in auditors if a.org_id), "not readable from this account"),
            "profile": args.profile or "default credential chain",
            "regions": ", ".join(regions),
            "document_count": str(sum(a.document_count for a in auditors)),
        }
        report = render_markdown(findings, meta, regions)
        if args.markdown == "-":
            print(report)
        else:
            with open(args.markdown, "w", encoding="utf-8") as handle:
                handle.write(report)
            print(f"markdown report written to {args.markdown}", file=sys.stderr)
            render(findings, args.json)
    else:
        render(findings, args.json)

    if args.fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[MUST_FIX if args.fail_on == "must-fix" else UNCHECKED]
    return 1 if any(SEVERITY_ORDER[f.severity] <= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
