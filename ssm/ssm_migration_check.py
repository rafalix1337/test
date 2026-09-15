#!/usr/bin/env python3
"""Read-only audit of AWS Systems Manager configuration that breaks when an
account is moved from one AWS Organization to another.

SSM documents themselves survive the move: they are account-scoped and the
account ID does not change. What breaks is everything wired to the *organization*
- SCPs, aws:PrincipalOrgID conditions, service-managed StackSets, org-wide
Resource Data Syncs and delegated administrators.

This script only calls Describe/Get/List APIs. It never mutates anything.
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
QUICK_SETUP_PREFIXES = ("AWS-QuickSetup", "AWSQuickSetup")

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


@dataclass
class Finding:
    severity: str
    check: str
    region: str
    resource: str
    detail: str
    action: str


def org_references(blob: Any) -> list[str]:
    """Return human-readable reasons why `blob` is tied to the current org."""
    text = blob if isinstance(blob, str) else json.dumps(blob)
    reasons: list[str] = []
    for key in ORG_CONDITION_KEYS:
        if key in text:
            reasons.append(f"condition key {key}")
    for org_id in sorted(set(ORG_ID_RE.findall(text))):
        reasons.append(f"organization id {org_id}")
    for ou_id in sorted(set(OU_ID_RE.findall(text))):
        reasons.append(f"organizational unit {ou_id}")
    return reasons


class Auditor:
    def __init__(self, session: boto3.Session, region: str, verbose: bool) -> None:
        self.session = session
        self.region = region
        self.verbose = verbose
        self.findings: list[Finding] = []
        self._clients: dict[str, Any] = {}
        self.account_id = ""
        self.org_id = ""
        self.org_account_ids: set[str] = set()

    # -- plumbing ---------------------------------------------------------

    def client(self, name: str):
        if name not in self._clients:
            self._clients[name] = self.session.client(name, region_name=self.region)
        return self._clients[name]

    def add(self, severity: str, check: str, resource: str, detail: str, action: str) -> None:
        self.findings.append(
            Finding(severity, check, self.region, resource, detail, action)
        )

    def skipped(self, check: str, err: Exception) -> None:
        code = ""
        if isinstance(err, ClientError):
            code = err.response.get("Error", {}).get("Code", "")
        self.add(
            "INFO",
            check,
            "-",
            f"check skipped: {code or type(err).__name__}: {err}",
            "re-run with credentials that allow this call to get full coverage",
        )

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"  .. {message}", file=sys.stderr)

    def paginate(self, client_name: str, operation: str, key: str, **kwargs) -> Iterable[dict]:
        client = self.client(client_name)
        paginator = client.get_paginator(operation)
        for page in paginator.paginate(**kwargs):
            yield from page.get(key, [])

    # -- context ----------------------------------------------------------

    def load_context(self) -> None:
        try:
            self.account_id = self.client("sts").get_caller_identity()["Account"]
        except (ClientError, BotoCoreError) as err:
            raise SystemExit(f"cannot resolve caller identity in {self.region}: {err}")
        try:
            org = self.client("organizations").describe_organization()["Organization"]
            self.org_id = org["Id"]
            management_account = org["MasterAccountId"]
            role = "management account" if management_account == self.account_id else "member account"
            self.add(
                "INFO",
                "organization",
                f"account {self.account_id}",
                f"currently a {role} of {self.org_id} (management account {management_account})",
                "account id stays the same after the move; organization id does not",
            )
        except (ClientError, BotoCoreError) as err:
            self.skipped("organization", err)
        try:
            self.org_account_ids = {
                a["Id"] for a in self.paginate("organizations", "list_accounts", "Accounts")
            }
        except (ClientError, BotoCoreError):
            pass  # member accounts cannot list; sharing check degrades gracefully

    # -- checks -----------------------------------------------------------

    def check_documents(self) -> None:
        """Self-owned documents: inventory, sharing, and embedded org/OU ids."""
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
            self.skipped("documents", err)
            return

        self.add(
            "INFO",
            "documents",
            f"{len(docs)} document(s) owned by this account",
            "documents are account-scoped and survive the migration untouched, "
            "including versions, default version and tags",
            "no action needed for the documents themselves",
        )

        ssm = self.client("ssm")
        for doc in docs:
            name = doc["Name"]
            self.log(f"document {name}")

            # Sharing: account ids survive, but in-org targets become external.
            try:
                perm = ssm.describe_document_permission(Name=name, PermissionType="Share")
                shared = perm.get("AccountIds", [])
            except (ClientError, BotoCoreError):
                shared = []

            if "all" in [s.lower() for s in shared]:
                self.add(
                    "MEDIUM",
                    "document-sharing",
                    f"document/{name}",
                    "shared publicly (All) - public sharing is independent of the "
                    "organization and stays public after the move",
                    "confirm the target organization allows public document sharing, "
                    "or unshare before migrating",
                )
            elif shared:
                in_org = sorted(set(shared) & self.org_account_ids)
                if in_org:
                    self.add(
                        "MEDIUM",
                        "document-sharing",
                        f"document/{name}",
                        "shared with account(s) in the current organization: "
                        + ", ".join(in_org)
                        + " - sharing survives, but becomes cross-organization",
                        "decide whether those accounts should still have access once "
                        "the account sits in a different organization",
                    )
                else:
                    self.add(
                        "LOW",
                        "document-sharing",
                        f"document/{name}",
                        "shared with " + ", ".join(sorted(shared)),
                        "sharing is by explicit account id, so it survives the move",
                    )

            # Content referencing the current org (automation target locations etc).
            try:
                content = ssm.get_document(Name=name)["Content"]
            except (ClientError, BotoCoreError):
                continue
            reasons = org_references(content)
            if reasons:
                self.add(
                    "HIGH",
                    "document-content",
                    f"document/{name}",
                    "document body is pinned to the current organization: "
                    + "; ".join(reasons),
                    "rewrite the document for the target organization id / OU ids "
                    "before or immediately after the move",
                )

    def check_public_sharing_setting(self) -> None:
        try:
            setting = self.client("ssm").get_service_setting(
                SettingId="/ssm/documents/console/public-sharing-permission"
            )["ServiceSetting"]
        except (ClientError, BotoCoreError) as err:
            self.skipped("public-sharing-setting", err)
            return
        value = setting.get("SettingValue", "")
        if value == "Enable":
            self.add(
                "LOW",
                "public-sharing-setting",
                "/ssm/documents/console/public-sharing-permission",
                "public document sharing is allowed in this account",
                "the target organization may forbid this via SCP; align the setting "
                "with the new organization's baseline",
            )

    def check_resource_data_syncs(self) -> None:
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
                self.skipped(f"resource-data-sync/{sync_type}", err)
                continue

            for sync in syncs:
                name = sync.get("SyncName", "?")
                source = sync.get("SyncSource") or {}
                source_type = source.get("SourceType", "")
                if source_type == "AwsOrganizations":
                    detail = "aggregates inventory from the current organization"
                    if source.get("AwsOrganizationsSource", {}).get("OrganizationSourceType"):
                        detail += (
                            f" ({source['AwsOrganizationsSource']['OrganizationSourceType']})"
                        )
                    self.add(
                        "HIGH",
                        "resource-data-sync",
                        f"resource-data-sync/{name}",
                        detail + " - breaks the moment the organization changes",
                        "delete and recreate the sync against the target organization",
                    )
                else:
                    bucket = (sync.get("S3Destination") or {}).get("BucketName", "")
                    self.add(
                        "LOW",
                        "resource-data-sync",
                        f"resource-data-sync/{name}",
                        f"{sync_type} sync"
                        + (f" to bucket {bucket}" if bucket else ""),
                        "check the destination bucket/KMS policy for organization "
                        "conditions (reported separately if reachable)",
                    )

    def check_delegated_administrators(self) -> None:
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
            self.skipped("delegated-administrator", err)
            return
        for admin in admins:
            severity = "HIGH" if admin["Id"] == self.account_id else "INFO"
            self.add(
                severity,
                "delegated-administrator",
                f"account/{admin['Id']}",
                "delegated administrator for ssm.amazonaws.com"
                + (" - this is the account being migrated" if severity == "HIGH" else ""),
                "register a delegated administrator in the target organization; "
                "Change Manager and Explorer aggregation stop working until then",
            )

    def check_vpc_endpoints(self) -> None:
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
            self.skipped("vpc-endpoints", err)
            return

        for endpoint in endpoints:
            service = endpoint.get("ServiceName", "")
            if not service.endswith(SSM_ENDPOINT_SUFFIXES):
                continue
            policy = endpoint.get("PolicyDocument") or ""
            reasons = org_references(policy)
            if reasons:
                self.add(
                    "HIGH",
                    "vpc-endpoint-policy",
                    f"{endpoint['VpcEndpointId']} ({service})",
                    "endpoint policy is pinned to the current organization: "
                    + "; ".join(reasons),
                    "update the policy for the new organization id, otherwise "
                    "Session Manager / SSM Agent traffic is denied after the move",
                )

    def check_session_manager_targets(self) -> None:
        """Session Manager log bucket + KMS key policies."""
        try:
            content = self.client("ssm").get_document(Name="SSM-SessionManagerRunShell")["Content"]
            inputs = json.loads(content).get("inputs", {})
        except (ClientError, BotoCoreError, ValueError) as err:
            self.skipped("session-manager-preferences", err)
            return

        bucket = inputs.get("s3BucketName") or ""
        if bucket:
            self.check_bucket_policy(bucket, "Session Manager session logs")
        key_id = inputs.get("kmsKeyId") or ""
        if key_id:
            self.check_key_policy(key_id, "Session Manager encryption")

    def check_bucket_policy(self, bucket: str, purpose: str) -> None:
        try:
            policy = self.client("s3").get_bucket_policy(Bucket=bucket)["Policy"]
        except (ClientError, BotoCoreError) as err:
            self.skipped(f"bucket-policy/{bucket}", err)
            return
        reasons = org_references(policy)
        if reasons:
            self.add(
                "HIGH",
                "bucket-policy",
                f"s3://{bucket}",
                f"{purpose} bucket policy is pinned to the current organization: "
                + "; ".join(reasons),
                "update the policy for the new organization id before the move, "
                "or writes from this account start failing with AccessDenied",
            )

    def check_key_policy(self, key_id: str, purpose: str) -> None:
        try:
            policy = self.client("kms").get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
        except (ClientError, BotoCoreError) as err:
            self.skipped(f"kms-key-policy/{key_id}", err)
            return
        reasons = org_references(policy)
        if reasons:
            self.add(
                "HIGH",
                "kms-key-policy",
                f"kms/{key_id}",
                f"{purpose} key policy is pinned to the current organization: "
                + "; ".join(reasons),
                "grant the account explicitly, or update the organization condition "
                "for the target organization",
            )

    def check_service_managed_stacks(self) -> None:
        """Stack instances pushed from the org - Quick Setup rides on these."""
        try:
            stacks = list(
                self.paginate(
                    "cloudformation",
                    "list_stacks",
                    "StackSummaries",
                    StackStatusFilter=[
                        "CREATE_COMPLETE",
                        "UPDATE_COMPLETE",
                        "UPDATE_ROLLBACK_COMPLETE",
                        "IMPORT_COMPLETE",
                    ],
                )
            )
        except (ClientError, BotoCoreError) as err:
            self.skipped("service-managed-stacks", err)
            return

        for stack in stacks:
            name = stack["StackName"]
            if not name.startswith("StackSet-"):
                continue
            severity = "MEDIUM"
            note = "stack instance deployed from an organization StackSet"
            if any(p in name for p in QUICK_SETUP_PREFIXES):
                severity = "HIGH"
                note = "SSM Quick Setup stack instance deployed from an organization StackSet"
            self.add(
                severity,
                "service-managed-stack",
                f"stack/{name}",
                note
                + " - leaving the OU removes or orphans it, taking its SSM "
                "associations and roles with it",
                "re-deploy the equivalent configuration from the target organization "
                "after the move",
            )

    def check_associations(self) -> None:
        try:
            associations = list(
                self.paginate("ssm", "list_associations", "Associations")
            )
        except (ClientError, BotoCoreError) as err:
            self.skipped("associations", err)
            return

        for assoc in associations:
            name = assoc.get("Name", "")
            assoc_name = assoc.get("AssociationName", "") or assoc.get("AssociationId", "")
            if any(name.startswith(p) or assoc_name.startswith(p) for p in QUICK_SETUP_PREFIXES):
                self.add(
                    "HIGH",
                    "quick-setup-association",
                    f"association/{assoc_name} ({name})",
                    "created by Quick Setup from the organization management account",
                    "expect it to disappear with its StackSet; re-provision host "
                    "management / patching from the target organization",
                )

    # -- driver -----------------------------------------------------------

    def run(self) -> list[Finding]:
        self.load_context()
        for check in (
            self.check_documents,
            self.check_public_sharing_setting,
            self.check_resource_data_syncs,
            self.check_delegated_administrators,
            self.check_vpc_endpoints,
            self.check_session_manager_targets,
            self.check_service_managed_stacks,
            self.check_associations,
        ):
            self.log(f"running {check.__name__}")
            try:
                check()
            except (ClientError, BotoCoreError) as err:  # defensive
                self.skipped(check.__name__, err)
        return self.findings


SEVERITY_BLURB = {
    "HIGH": "Fix before the move. These fail closed: the affected calls start "
    "returning AccessDenied, or the configuration disappears with its StackSet.",
    "MEDIUM": "Decide before the move. Nothing breaks on its own, but the blast "
    "radius or the audience changes once the account sits in a different organization.",
    "LOW": "Informational risk. Worth a look while aligning with the target "
    "organization's baseline.",
    "INFO": "Context and skipped checks. A skipped check is a blind spot, not a "
    "clean result.",
}


def md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(findings: list[Finding], meta: dict[str, str]) -> str:
    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.region, f.check))
    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    skipped = [f for f in findings if f.check and "check skipped" in f.detail]

    out: list[str] = []
    out.append("# SSM organization-migration readiness report")
    out.append("")
    out.append(
        "Read-only audit of Systems Manager configuration that breaks when this AWS "
        "account is moved to a different AWS Organization. SSM documents themselves "
        "survive the move untouched — the account ID does not change. Everything below "
        "is about configuration tied to the *organization*."
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
    ):
        out.append(f"| {label} | {md_escape(meta.get(key) or '-')} |")
    out.append("")

    out.append("## Summary")
    out.append("")
    out.append("| Severity | Findings |")
    out.append("| --- | --- |")
    for sev in SEVERITY_ORDER:
        out.append(f"| {sev} | {counts[sev]} |")
    out.append("")
    if counts["HIGH"]:
        out.append(
            f"**{counts['HIGH']} blocking finding(s).** Do not start the migration "
            "until each one below is resolved or explicitly accepted."
        )
    else:
        out.append(
            "**No blocking findings.** Note that the target organization's SCPs are "
            "not visible from this account and are not covered by this report."
        )
    out.append("")

    for sev in SEVERITY_ORDER:
        rows = [f for f in findings if f.severity == sev]
        if not rows:
            continue
        out.append(f"## {sev}")
        out.append("")
        out.append(f"_{SEVERITY_BLURB[sev]}_")
        out.append("")
        out.append("| Check | Region | Resource | Finding | Action |")
        out.append("| --- | --- | --- | --- | --- |")
        for f in rows:
            out.append(
                f"| `{md_escape(f.check)}` | {md_escape(f.region)} "
                f"| `{md_escape(f.resource)}` | {md_escape(f.detail)} "
                f"| {md_escape(f.action)} |"
            )
        out.append("")

    out.append("## Not covered by this report")
    out.append("")
    out.append(
        "- **SCPs of the target organization.** They apply the instant the account is "
        "invited, and no API exposes them from the source account. Diff the two "
        "organizations' policies by hand."
    )
    out.append(
        "- **Organization references in infrastructure code.** Grep the Terraform: "
        "`grep -rE 'PrincipalOrgID|ResourceOrgID|\\bo-[a-z0-9]{10,}' <infra-repo>`"
    )
    if skipped:
        out.append(
            f"- **{len(skipped)} check(s) skipped** for lack of permissions or "
            "unreachable resources, listed under INFO above. Treat them as blind spots."
        )
    out.append("")

    out.append("## Suggested order of work")
    out.append("")
    out.append("1. Resolve every HIGH finding above.")
    out.append("2. Diff source and target organization SCPs.")
    out.append("3. Perform the migration.")
    out.append(
        "4. Re-run this audit with `--fail-on medium` and re-provision Quick Setup "
        "and Resource Data Sync from the new organization."
    )
    out.append("")

    return "\n".join(out)


def render(findings: list[Finding], as_json: bool) -> None:
    if as_json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
        return

    findings = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.region, f.check))
    current = None
    for finding in findings:
        if finding.severity != current:
            current = finding.severity
            print(f"\n=== {current} ===")
        print(f"[{finding.region}] {finding.check}: {finding.resource}")
        print(f"    {finding.detail}")
        print(f"    -> {finding.action}")

    counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in SEVERITY_ORDER}
    print(
        "\nsummary: "
        + ", ".join(f"{sev.lower()}={counts[sev]}" for sev in SEVERITY_ORDER)
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit SSM configuration that breaks when an AWS account "
        "moves to a different AWS Organization (read-only).",
    )
    parser.add_argument(
        "--profile",
        help="AWS named profile to use (default: the usual credential chain)",
    )
    parser.add_argument(
        "--region",
        help="Region, or comma-separated regions, to audit "
        "(default: the profile's configured region)",
    )
    parser.add_argument("--json", action="store_true", help="emit findings as JSON")
    parser.add_argument(
        "--markdown",
        nargs="?",
        const="ssm-migration-report.md",
        metavar="PATH",
        help="also write a Markdown report (default path: ssm-migration-report.md; "
        "use '-' to print it to stdout instead of the text report)",
    )
    parser.add_argument("--verbose", action="store_true", help="log progress to stderr")
    parser.add_argument(
        "--fail-on",
        choices=["high", "medium", "low", "never"],
        default="high",
        help="exit non-zero when a finding of this severity or worse exists "
        "(default: high)",
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
        return int(bool(sys.stderr.write("no region: pass --region or configure the profile\n")))

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
        }
        report = render_markdown(findings, meta)
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
    threshold = SEVERITY_ORDER[args.fail_on.upper()]
    return 1 if any(SEVERITY_ORDER[f.severity] <= threshold for f in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
