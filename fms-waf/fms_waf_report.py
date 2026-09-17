#!/usr/bin/env python3
"""Read-only inventory of Firewall Manager-managed AWS WAF web ACLs.

Finds every web ACL whose name starts with a prefix (default
`FMManagedWebACLV2-`, the name Firewall Manager gives the web ACLs it creates)
and reports, per region:

  * every rule attached to it, including the Firewall Manager pre- and
    post-process rule groups that a member account cannot edit,
  * every AWS resource the web ACL is associated with,
  * a traffic overview from CloudWatch — allowed / counted / blocked requests
    over the last N days, for the web ACL as a whole and for each rule.

`global` means WAF scope CLOUDFRONT, which lives only in us-east-1; every other
region is queried with scope REGIONAL.

Output is a Markdown report with one table per region. Every call is
List*/Get*/Describe* — the script never mutates anything.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Iterator

try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError, ParamValidationError
except ImportError:  # pragma: no cover
    sys.exit("boto3 is required: pip install boto3")


GLOBAL_LABEL = "global"
DEFAULT_REGIONS = ("global", "us-east-1", "us-west-2", "eu-central-1", "eu-west-2")
DEFAULT_PREFIX = "FMManagedWebACLV2-"
DEFAULT_OUTPUT = "fms-waf-report.md"

NAMESPACE = "AWS/WAFV2"
METRICS = ("AllowedRequests", "CountedRequests", "BlockedRequests")
ALL_RULES = "ALL"

RESOURCE_TYPES = (
    "APPLICATION_LOAD_BALANCER",
    "API_GATEWAY",
    "APPSYNC",
    "COGNITO_USER_POOL",
    "APP_RUNNER_SERVICE",
    "VERIFIED_ACCESS_INSTANCE",
    "AMPLIFY",
)

# FMManagedWebACLV2-<policy name>-<epoch millis>
FMS_NAME_RE = re.compile(r"^FMManagedWebACLV2-(?P<policy>.+)-(?P<stamp>\d{10,})$")

PRE = "pre-process (Firewall Manager)"
OWN = "account rules"
POST = "post-process (Firewall Manager)"


@dataclass
class Rule:
    stage: str
    priority: Any
    name: str
    kind: str
    detail: str
    action: str
    metric: str
    allowed: float = 0.0
    counted: float = 0.0
    blocked: float = 0.0


@dataclass
class WebAcl:
    name: str
    acl_id: str
    arn: str
    policy: str
    capacity: Any
    default_action: str
    managed_by_fms: bool
    retrofitted: bool
    label_namespace: str
    rules: list[Rule] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    allowed: float = 0.0
    counted: float = 0.0
    blocked: float = 0.0

    @property
    def total(self) -> float:
        return self.allowed + self.counted + self.blocked


@dataclass
class RegionReport:
    label: str
    scope: str
    api_region: str
    web_acls: list[WebAcl] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    scanned: int = 0


def short(err: Exception) -> str:
    if isinstance(err, ClientError):
        return err.response.get("Error", {}).get("Code", "ClientError")
    return type(err).__name__


def first_key(blob: Any) -> str:
    if isinstance(blob, dict) and blob:
        return next(iter(blob))
    return "-"


def chunks(items: list[Any], size: int) -> Iterator[list[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def field_names(blob: Any) -> str:
    """Readable name of a FieldToMatch."""
    if not isinstance(blob, dict) or not blob:
        return "?"
    key = first_key(blob)
    body = blob.get(key) or {}
    if key == "SingleHeader" and isinstance(body, dict):
        return f"header:{body.get('Name', '?')}"
    if key == "SingleQueryArgument" and isinstance(body, dict):
        return f"arg:{body.get('Name', '?')}"
    return key


def action_label(blob: Any) -> str:
    key = first_key(blob)
    return {"None": "none (group actions apply)"}.get(key, key.lower())


def describe_nested(stmt: Any, depth: int) -> str:
    """describe_statement() flattened to one string, keeping the statement kind."""
    kind, detail = describe_statement(stmt, depth)
    if detail in ("-", ""):
        return kind
    return f"{kind}({detail})"


def describe_statement(stmt: Any, depth: int = 0) -> tuple[str, str]:
    """Return (kind, human-readable detail) for a WAFv2 statement."""
    if not isinstance(stmt, dict) or not stmt:
        return ("-", "-")
    key = first_key(stmt)
    body = stmt.get(key) or {}

    if key == "ManagedRuleGroupStatement":
        vendor = body.get("VendorName", "?")
        name = body.get("Name", "?")
        version = body.get("Version") or "default (auto-update)"
        bits = [f"`{vendor}/{name}` @ {version}"]
        excluded = [r.get("Name", "?") for r in body.get("ExcludedRules") or []]
        if excluded:
            bits.append("excluded: " + ", ".join(excluded))
        overrides = body.get("RuleActionOverrides") or []
        if overrides:
            bits.append(
                "overrides: "
                + ", ".join(
                    f"{o.get('Name', '?')} to {action_label(o.get('ActionToUse'))}" for o in overrides
                )
            )
        scope_down = body.get("ScopeDownStatement")
        if scope_down and depth < 3:
            bits.append("scope-down: " + describe_nested(scope_down, depth + 1))
        return ("managed rule group", "; ".join(bits))

    if key == "RuleGroupReferenceStatement":
        arn = body.get("ARN", "?")
        bits = [f"`{arn.rsplit('/', 2)[-2] if arn.count('/') >= 2 else arn}`"]
        excluded = [r.get("Name", "?") for r in body.get("ExcludedRules") or []]
        if excluded:
            bits.append("excluded: " + ", ".join(excluded))
        bits.append(arn)
        return ("custom rule group", " — ".join(bits))

    if key == "RateBasedStatement":
        window = body.get("EvaluationWindowSec", 300)
        aggregate = body.get("AggregateKeyType", "IP")
        detail = f"limit {body.get('Limit', '?')} per {window}s, key {aggregate}"
        scope_down = body.get("ScopeDownStatement")
        if scope_down and depth < 3:
            detail += "; scope-down: " + describe_nested(scope_down, depth + 1)
        return ("rate-based", detail)

    if key == "GeoMatchStatement":
        codes = body.get("CountryCodes") or []
        return ("geo match", ", ".join(codes) if codes else "forwarded-IP config only")

    if key == "IPSetReferenceStatement":
        arn = body.get("ARN", "?")
        return ("IP set", arn)

    if key == "RegexPatternSetReferenceStatement":
        return ("regex pattern set", f"{body.get('ARN', '?')} on {field_names(body.get('FieldToMatch'))}")

    if key in ("ByteMatchStatement",):
        needle = body.get("SearchString")
        if isinstance(needle, bytes):
            needle = needle.decode("utf-8", "replace")
        return (
            "byte match",
            f"{body.get('PositionalConstraint', '?')} '{needle}' on {field_names(body.get('FieldToMatch'))}",
        )

    if key in ("SqliMatchStatement", "XssMatchStatement", "RegexMatchStatement"):
        pretty = {"SqliMatchStatement": "SQLi match", "XssMatchStatement": "XSS match"}.get(
            key, "regex match"
        )
        return (pretty, f"on {field_names(body.get('FieldToMatch'))}")

    if key == "SizeConstraintStatement":
        return (
            "size constraint",
            f"{field_names(body.get('FieldToMatch'))} {body.get('ComparisonOperator', '?')} {body.get('Size', '?')}",
        )

    if key == "LabelMatchStatement":
        return ("label match", f"{body.get('Scope', '?')} = {body.get('Key', '?')}")

    if key in ("AndStatement", "OrStatement"):
        joiner = " AND " if key == "AndStatement" else " OR "
        parts = body.get("Statements") or []
        if depth >= 3:
            return (key[:-9].lower(), f"{len(parts)} nested statements")
        inner = joiner.join(describe_nested(p, depth + 1) for p in parts)
        return (key[:-9].lower(), inner or "-")

    if key == "NotStatement":
        if depth >= 3:
            return ("not", "nested statement")
        return ("not", "NOT " + describe_nested(body.get("Statement"), depth + 1))

    return (key, "-")


class Collector:
    def __init__(self, session: boto3.Session, label: str, days: int, prefix: str, verbose: bool):
        self.session = session
        self.label = label
        self.prefix = prefix
        self.verbose = verbose
        self.is_global = label.lower() == GLOBAL_LABEL
        self.scope = "CLOUDFRONT" if self.is_global else "REGIONAL"
        self.api_region = "us-east-1" if self.is_global else label
        self.end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        self.start = self.end - timedelta(days=days)
        self.report = RegionReport(label=label, scope=self.scope, api_region=self.api_region)
        self._clients: dict[str, Any] = {}

    def client(self, name: str):
        if name not in self._clients:
            self._clients[name] = self.session.client(name, region_name=self.api_region)
        return self._clients[name]

    def log(self, message: str) -> None:
        if self.verbose:
            print(f"[{self.label}] {message}", file=sys.stderr)

    def warn(self, message: str) -> None:
        self.report.warnings.append(message)
        self.log(f"warning: {message}")

    # ---------------------------------------------------------------- discovery

    def list_web_acls(self) -> list[dict]:
        wafv2 = self.client("wafv2")
        found: list[dict] = []
        marker: str | None = None
        while True:
            kwargs: dict[str, Any] = {"Scope": self.scope, "Limit": 100}
            if marker:
                kwargs["NextMarker"] = marker
            try:
                page = wafv2.list_web_acls(**kwargs)
            except (ClientError, BotoCoreError) as err:
                self.warn(f"list-web-acls failed: {short(err)}")
                return found
            found.extend(page.get("WebACLs") or [])
            marker = page.get("NextMarker")
            if not marker or not page.get("WebACLs"):
                break
        self.report.scanned = len(found)
        return [a for a in found if a.get("Name", "").startswith(self.prefix)]

    def get_web_acl(self, summary: dict) -> WebAcl | None:
        name = summary.get("Name", "")
        try:
            acl = self.client("wafv2").get_web_acl(
                Name=name, Scope=self.scope, Id=summary.get("Id", "")
            )["WebACL"]
        except (ClientError, BotoCoreError) as err:
            self.warn(f"get-web-acl failed for {name}: {short(err)}")
            return None

        match = FMS_NAME_RE.match(name)
        entry = WebAcl(
            name=name,
            acl_id=acl.get("Id", ""),
            arn=acl.get("ARN", ""),
            policy=match.group("policy") if match else "-",
            capacity=acl.get("Capacity", "-"),
            default_action=action_label(acl.get("DefaultAction")),
            managed_by_fms=bool(acl.get("ManagedByFirewallManager")),
            retrofitted=bool(acl.get("RetrofittedByFirewallManager")),
            label_namespace=acl.get("LabelNamespace", "-"),
        )
        entry.rules = self.collect_rules(acl)
        entry.resources = self.collect_resources(entry.arn)
        self.attach_metrics(entry)
        return entry

    def collect_rules(self, acl: dict) -> list[Rule]:
        rules: list[Rule] = []

        def by_priority(items: Iterable[dict]) -> list[dict]:
            """WAF evaluates in ascending Priority; the API does not promise that order."""
            return sorted(items or [], key=lambda i: (i.get("Priority") is None, i.get("Priority", 0)))

        def add_fms(stage: str, groups: Iterable[dict]) -> None:
            for group in by_priority(groups):
                kind, detail = describe_statement(group.get("FirewallManagerStatement"))
                rules.append(
                    Rule(
                        stage=stage,
                        priority=group.get("Priority", "-"),
                        name=group.get("Name", "-"),
                        kind=kind,
                        detail=detail,
                        action=action_label(group.get("OverrideAction")),
                        metric=(group.get("VisibilityConfig") or {}).get("MetricName", ""),
                    )
                )

        add_fms(PRE, acl.get("PreProcessFirewallManagerRuleGroups") or [])

        for rule in by_priority(acl.get("Rules")):
            kind, detail = describe_statement(rule.get("Statement"))
            if rule.get("Action"):
                action = action_label(rule.get("Action"))
            elif rule.get("OverrideAction"):
                action = f"override: {action_label(rule.get('OverrideAction'))}"
            else:
                action = "-"
            rules.append(
                Rule(
                    stage=OWN,
                    priority=rule.get("Priority", "-"),
                    name=rule.get("Name", "-"),
                    kind=kind,
                    detail=detail,
                    action=action,
                    metric=(rule.get("VisibilityConfig") or {}).get("MetricName", ""),
                )
            )

        add_fms(POST, acl.get("PostProcessFirewallManagerRuleGroups") or [])
        return rules

    def collect_resources(self, arn: str) -> list[str]:
        if not arn:
            return []
        if self.is_global:
            return self.collect_cloudfront(arn)

        wafv2 = self.client("wafv2")
        found: list[str] = []
        for resource_type in RESOURCE_TYPES:
            try:
                found.extend(
                    wafv2.list_resources_for_web_acl(WebACLArn=arn, ResourceType=resource_type).get(
                        "ResourceArns"
                    )
                    or []
                )
            except ParamValidationError:
                continue  # resource type unknown to this botocore version
            except ClientError as err:
                code = err.response.get("Error", {}).get("Code", "")
                if code in ("WAFInvalidParameterException", "ValidationException"):
                    continue
                self.warn(f"list-resources-for-web-acl({resource_type}) failed: {code}")
            except BotoCoreError as err:
                self.warn(f"list-resources-for-web-acl({resource_type}) failed: {short(err)}")
        return sorted(dict.fromkeys(found))

    def collect_cloudfront(self, arn: str) -> list[str]:
        found: list[str] = []
        try:
            paginator = self.client("cloudfront").get_paginator("list_distributions")
            for page in paginator.paginate():
                for dist in (page.get("DistributionList") or {}).get("Items") or []:
                    if dist.get("WebACLId") != arn:
                        continue
                    aliases = ((dist.get("Aliases") or {}).get("Items")) or []
                    label = dist.get("DomainName", dist.get("Id", "?"))
                    if aliases:
                        label += " (" + ", ".join(aliases) + ")"
                    found.append(label)
        except (ClientError, BotoCoreError) as err:
            self.warn(f"cloudfront list-distributions failed: {short(err)}")
        return sorted(found)

    # ------------------------------------------------------------------ metrics

    def discover_dimensions(self, acl_name: str) -> dict[str, list[dict]]:
        """Map the Rule dimension value to the full dimension set CloudWatch uses."""
        found: dict[str, list[dict]] = {}
        try:
            paginator = self.client("cloudwatch").get_paginator("list_metrics")
            for page in paginator.paginate(
                Namespace=NAMESPACE, Dimensions=[{"Name": "WebACL", "Value": acl_name}]
            ):
                for metric in page.get("Metrics") or []:
                    dims = metric.get("Dimensions") or []
                    names = {d["Name"]: d["Value"] for d in dims}
                    if names.get("WebACL") != acl_name or "Rule" not in names:
                        continue
                    previous = found.get(names["Rule"])
                    if previous is None or len(dims) > len(previous):
                        found[names["Rule"]] = dims
        except (ClientError, BotoCoreError) as err:
            self.warn(f"cloudwatch list-metrics failed for {acl_name}: {short(err)}")
        return found

    def fallback_dimensions(self, acl_name: str, rule: str) -> list[dict]:
        region_value = "Global" if self.is_global else self.api_region
        return [
            {"Name": "WebACL", "Value": acl_name},
            {"Name": "Rule", "Value": rule},
            {"Name": "Region", "Value": region_value},
        ]

    def attach_metrics(self, entry: WebAcl) -> None:
        discovered = self.discover_dimensions(entry.name)
        targets = [ALL_RULES] + [r.metric for r in entry.rules if r.metric]
        queries: list[dict] = []
        index: dict[str, tuple[str, str]] = {}
        for rule in dict.fromkeys(targets):
            dims = discovered.get(rule) or self.fallback_dimensions(entry.name, rule)
            for metric in METRICS:
                qid = f"q{len(queries)}"
                index[qid] = (rule, metric)
                queries.append(
                    {
                        "Id": qid,
                        "MetricStat": {
                            "Metric": {
                                "Namespace": NAMESPACE,
                                "MetricName": metric,
                                "Dimensions": dims,
                            },
                            "Period": 86400,
                            "Stat": "Sum",
                        },
                        "ReturnData": True,
                    }
                )

        totals: dict[tuple[str, str], float] = {}
        cloudwatch = self.client("cloudwatch")
        for chunk in chunks(queries, 450):
            try:
                paginator = cloudwatch.get_paginator("get_metric_data")
                for page in paginator.paginate(
                    MetricDataQueries=chunk,
                    StartTime=self.start,
                    EndTime=self.end,
                    ScanBy="TimestampAscending",
                ):
                    for item in page.get("MetricDataResults") or []:
                        key = index.get(item.get("Id", ""))
                        if key is None:
                            continue
                        totals[key] = totals.get(key, 0.0) + sum(item.get("Values") or [])
            except (ClientError, BotoCoreError) as err:
                self.warn(f"cloudwatch get-metric-data failed for {entry.name}: {short(err)}")
                return

        entry.allowed = totals.get((ALL_RULES, "AllowedRequests"), 0.0)
        entry.counted = totals.get((ALL_RULES, "CountedRequests"), 0.0)
        entry.blocked = totals.get((ALL_RULES, "BlockedRequests"), 0.0)
        for rule in entry.rules:
            if not rule.metric:
                continue
            rule.allowed = totals.get((rule.metric, "AllowedRequests"), 0.0)
            rule.counted = totals.get((rule.metric, "CountedRequests"), 0.0)
            rule.blocked = totals.get((rule.metric, "BlockedRequests"), 0.0)

    # --------------------------------------------------------------------- run

    def run(self) -> RegionReport:
        self.log(f"scope {self.scope} via {self.api_region}")
        for summary in self.list_web_acls():
            self.log(f"web ACL {summary.get('Name')}")
            entry = self.get_web_acl(summary)
            if entry:
                self.report.web_acls.append(entry)
        self.report.web_acls.sort(key=lambda a: a.name)
        return self.report


# --------------------------------------------------------------------- render


def md_cell(value: Any) -> str:
    text = "-" if value is None or value == "" else str(value)
    return text.replace("|", "\\|").replace("\n", "<br>")


def fmt(value: float) -> str:
    return f"{int(round(value)):,}"


def observations(acl: WebAcl) -> list[str]:
    notes: list[str] = []
    if not acl.resources:
        notes.append(
            "**Not associated with any resource** — the web ACL exists but inspects no traffic."
        )
    if acl.total == 0:
        notes.append("No requests recorded in the window — either no traffic, or metrics are off.")
    counted_only = [
        r
        for r in acl.rules
        if r.kind in ("managed rule group", "custom rule group")
        and r.action in ("count", "override: count")
    ]
    if counted_only:
        notes.append(
            "Rule group(s) in **count mode, blocking nothing**: "
            + ", ".join(f"`{r.name}`" for r in counted_only)
        )
    if acl.blocked == 0 and acl.counted > 0:
        notes.append(
            f"{fmt(acl.counted)} counted and 0 blocked — the web ACL is in observation mode."
        )
    if not acl.managed_by_fms:
        notes.append(
            "`ManagedByFirewallManager` is **false** despite the name — Firewall Manager no "
            "longer owns this web ACL, so it will not be reconciled or cleaned up."
        )
    if acl.retrofitted:
        notes.append("Retrofitted by Firewall Manager from a pre-existing web ACL.")
    return notes


def render_markdown(reports: list[RegionReport], meta: dict[str, str]) -> str:
    out: list[str] = []
    out.append("# Firewall Manager WAF inventory")
    out.append("")
    out.append(
        "Every web ACL matching the name prefix below, with its full rule chain, the "
        "resources it is associated with, and its request counts from CloudWatch. "
        "`global` is WAF scope CLOUDFRONT, queried in us-east-1; all other rows are "
        "scope REGIONAL."
    )
    out.append("")

    out.append("## Scope")
    out.append("")
    out.append("| Field | Value |")
    out.append("| --- | --- |")
    for label, key in (
        ("Generated (UTC)", "generated_at"),
        ("Account", "account_id"),
        ("Profile", "profile"),
        ("Name prefix", "prefix"),
        ("Metric window", "window"),
        ("Regions", "regions"),
    ):
        out.append(f"| {label} | {md_cell(meta.get(key))} |")
    out.append("")

    out.append("## Summary")
    out.append("")
    out.append("| Region | Scope | Web ACLs | Rules | Resources | Allowed | Counted | Blocked |")
    out.append("| --- | --- | --: | --: | --: | --: | --: | --: |")
    for report in reports:
        out.append(
            "| {region} | {scope} | {acls} | {rules} | {resources} | {allowed} | {counted} | {blocked} |".format(
                region=md_cell(report.label),
                scope=report.scope,
                acls=len(report.web_acls),
                rules=sum(len(a.rules) for a in report.web_acls),
                resources=sum(len(a.resources) for a in report.web_acls),
                allowed=fmt(sum(a.allowed for a in report.web_acls)),
                counted=fmt(sum(a.counted for a in report.web_acls)),
                blocked=fmt(sum(a.blocked for a in report.web_acls)),
            )
        )
    out.append(
        "| **total** | | **{acls}** | **{rules}** | **{resources}** | **{allowed}** | **{counted}** | **{blocked}** |".format(
            acls=sum(len(r.web_acls) for r in reports),
            rules=sum(len(a.rules) for r in reports for a in r.web_acls),
            resources=sum(len(a.resources) for r in reports for a in r.web_acls),
            allowed=fmt(sum(a.allowed for r in reports for a in r.web_acls)),
            counted=fmt(sum(a.counted for r in reports for a in r.web_acls)),
            blocked=fmt(sum(a.blocked for r in reports for a in r.web_acls)),
        )
    )
    out.append("")

    for report in reports:
        out.append(f"## {report.label}")
        out.append("")
        out.append(
            f"_Scope `{report.scope}`, queried via `{report.api_region}`. "
            f"{report.scanned} web ACL(s) in the region, {len(report.web_acls)} matching the prefix._"
        )
        out.append("")

        if report.warnings:
            out.append("> **Incomplete data**")
            for warning in dict.fromkeys(report.warnings):
                out.append(f"> - {md_cell(warning)}")
            out.append("")

        if not report.web_acls:
            out.append("No web ACL matches the prefix in this region.")
            out.append("")
            continue

        out.append(
            "| Web ACL | Policy | WCU | Default action | Rules | Resources | Allowed | Counted | Blocked |"
        )
        out.append("| --- | --- | --: | --- | --: | --: | --: | --: | --: |")
        for acl in report.web_acls:
            out.append(
                "| `{name}` | {policy} | {wcu} | {default} | {rules} | {resources} | {allowed} | {counted} | {blocked} |".format(
                    name=md_cell(acl.name),
                    policy=md_cell(acl.policy),
                    wcu=md_cell(acl.capacity),
                    default=md_cell(acl.default_action),
                    rules=len(acl.rules),
                    resources=len(acl.resources),
                    allowed=fmt(acl.allowed),
                    counted=fmt(acl.counted),
                    blocked=fmt(acl.blocked),
                )
            )
        out.append("")

        for acl in report.web_acls:
            out.append(f"### {acl.name}")
            out.append("")
            out.append(f"`{acl.arn}`")
            out.append("")

            notes = observations(acl)
            if notes:
                for note in notes:
                    out.append(f"- {note}")
                out.append("")

            out.append("#### Rules")
            out.append("")
            if acl.rules:
                out.append(
                    "| Stage | Prio | Rule | Type | Detail | Action | Allowed | Counted | Blocked |"
                )
                out.append("| --- | --: | --- | --- | --- | --- | --: | --: | --: |")
                for rule in acl.rules:
                    out.append(
                        "| {stage} | {prio} | `{name}` | {kind} | {detail} | {action} | {allowed} | {counted} | {blocked} |".format(
                            stage=md_cell(rule.stage),
                            prio=md_cell(rule.priority),
                            name=md_cell(rule.name),
                            kind=md_cell(rule.kind),
                            detail=md_cell(rule.detail),
                            action=md_cell(rule.action),
                            allowed=fmt(rule.allowed),
                            counted=fmt(rule.counted),
                            blocked=fmt(rule.blocked),
                        )
                    )
            else:
                out.append("_No rules._")
            out.append("")

            out.append("#### Associated resources")
            out.append("")
            if acl.resources:
                for resource in acl.resources:
                    out.append(f"- `{md_cell(resource)}`")
            else:
                out.append("_None._")
            out.append("")

    out.append("## Reading this report")
    out.append("")
    out.append(
        "- Rules in the `pre-process (Firewall Manager)` and `post-process (Firewall Manager)` "
        "stages are pushed by a Firewall Manager policy. They cannot be edited from this "
        "account — local changes are reverted on the next compliance run."
    )
    out.append(
        "- An action of `count` or `override: count` on a rule group means it matches and "
        "reports but **blocks nothing**. A web ACL can look fully configured and still be "
        "passing everything through."
    )
    out.append(
        "- Per-rule counts come from the rule's own CloudWatch metric. Rules that never "
        "matched publish no metric, and show as 0."
    )
    out.append(
        "- Allowed + counted + blocked does not have to equal total requests: CAPTCHA and "
        "challenge outcomes are counted separately by WAF."
    )
    out.append("")
    return "\n".join(out)


# ----------------------------------------------------------------------- main


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventory Firewall Manager-managed AWS WAF web ACLs — rules, "
        "associated resources and request counts — as a Markdown report (read-only).",
    )
    parser.add_argument(
        "--profile",
        help="AWS named profile to use (default: the usual credential chain)",
    )
    parser.add_argument(
        "--regions",
        default=",".join(DEFAULT_REGIONS),
        metavar="LIST",
        help="comma-separated regions; 'global' means WAF scope CLOUDFRONT "
        f"(default: {','.join(DEFAULT_REGIONS)})",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=7,
        help="size of the CloudWatch window in days (default: 7)",
    )
    parser.add_argument(
        "--prefix",
        default=DEFAULT_PREFIX,
        help=f"web ACL name prefix to match; pass '' for every web ACL "
        f"(default: {DEFAULT_PREFIX})",
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT,
        metavar="PATH",
        help=f"Markdown output path, or '-' for stdout (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument("--verbose", action="store_true", help="log progress to stderr")
    args = parser.parse_args()

    if args.days < 1:
        parser.error("--days must be at least 1")

    regions: list[str] = []
    for chunk in args.regions.split(","):
        label = chunk.strip()
        if label and label not in regions:
            regions.append(label)
    if not regions:
        parser.error("--regions is empty")

    try:
        session = boto3.Session(profile_name=args.profile) if args.profile else boto3.Session()
    except BotoCoreError as err:
        raise SystemExit(str(err))

    try:
        account_id = session.client("sts", region_name="us-east-1").get_caller_identity()["Account"]
    except (ClientError, BotoCoreError) as err:
        raise SystemExit(f"cannot use these credentials: {err}")

    reports: list[RegionReport] = []
    for label in regions:
        collector = Collector(session, label, args.days, args.prefix, args.verbose)
        reports.append(collector.run())

    window_end = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    window_start = window_end - timedelta(days=args.days)
    meta = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ"),
        "account_id": account_id,
        "profile": args.profile or "default credential chain",
        "prefix": args.prefix or "(none — every web ACL)",
        "window": f"last {args.days} day(s): "
        f"{window_start.strftime('%Y-%m-%d %H:%MZ')} to {window_end.strftime('%Y-%m-%d %H:%MZ')}",
        "regions": ", ".join(regions),
    }

    report = render_markdown(reports, meta)
    if args.output == "-":
        print(report)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(report)
        total = sum(len(r.web_acls) for r in reports)
        print(
            f"{total} web ACL(s) across {len(regions)} region(s) — report written to {args.output}",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
