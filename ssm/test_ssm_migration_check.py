#!/usr/bin/env python3
"""Unit tests for ssm_migration_check. No AWS calls: every client is stubbed.

Run:  python -m unittest test_ssm_migration_check -v
"""

import unittest

from botocore.exceptions import ClientError

from ssm_migration_check import (
    Finding,
    MUST_FIX,
    UNCHECKED,
    Auditor,
    md_escape,
    org_references,
    render_markdown,
)

ORG_POLICY = (
    '{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt",'
    '"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc1234567"}}}]}'
)
CLEAN_POLICY = (
    '{"Statement":[{"Effect":"Allow","Principal":{"AWS":"111122223333"},'
    '"Action":"kms:Decrypt"}]}'
)


def client_error(code, operation="Op"):
    return ClientError({"Error": {"Code": code, "Message": code}}, operation)


class FakePaginator:
    def __init__(self, pages):
        self.pages = pages

    def paginate(self, **kwargs):
        return self.pages


class FakeClient:
    """Stub AWS client. `paginate:<op>` supplies pages; other keys are methods."""

    def __init__(self, **ops):
        self._ops = ops
        self.calls = []

    def get_paginator(self, operation):
        return FakePaginator(self._ops.get(f"paginate:{operation}", []))

    def __getattr__(self, name):
        ops = object.__getattribute__(self, "_ops")
        if name not in ops:
            raise AttributeError(name)
        value = ops[name]

        def call(**kwargs):
            object.__getattribute__(self, "calls").append((name, kwargs))
            if isinstance(value, Exception):
                raise value
            return value(**kwargs) if callable(value) else value

        return call


def make_auditor(**clients):
    auditor = Auditor(session=None, region="eu-west-1", verbose=False)
    auditor.account_id = "032851495384"
    auditor.org_id = "o-abc1234567"
    auditor.client = lambda name: clients[name]
    return auditor


class TestOrgReferences(unittest.TestCase):
    def test_reports_condition_key_and_org_id(self):
        self.assertEqual(
            org_references(ORG_POLICY), ["aws:PrincipalOrgID", "o-abc1234567"]
        )

    def test_reports_organizational_unit(self):
        self.assertIn("ou-ab12-abcd1234", org_references("target ou-ab12-abcd1234"))

    def test_clean_policy_yields_nothing(self):
        self.assertEqual(org_references(CLEAN_POLICY), [])

    def test_accepts_dicts(self):
        self.assertIn("aws:ResourceOrgID", org_references({"k": "aws:ResourceOrgID"}))


class TestKeyPolicy(unittest.TestCase):
    def test_org_condition_is_must_fix(self):
        auditor = make_auditor(kms=FakeClient(get_key_policy={"Policy": ORG_POLICY}))
        auditor.check_key_policy("key-1", "SecureString parameters")
        self.assertEqual(len(auditor.findings), 1)
        finding = auditor.findings[0]
        self.assertEqual(finding.severity, MUST_FIX)
        self.assertIn("aws:PrincipalOrgID", finding.evidence)
        self.assertIn("SecureString parameters", finding.evidence)

    def test_clean_policy_is_silent(self):
        auditor = make_auditor(kms=FakeClient(get_key_policy={"Policy": CLEAN_POLICY}))
        auditor.check_key_policy("key-1", "x")
        self.assertEqual(auditor.findings, [])

    def test_aws_managed_key_is_not_fetched(self):
        kms = FakeClient(get_key_policy={"Policy": ORG_POLICY})
        auditor = make_auditor(kms=kms)
        auditor.check_key_policy("alias/aws/ssm", "x")
        self.assertEqual(auditor.findings, [])
        self.assertEqual(kms.calls, [])

    def test_same_key_is_only_reported_once(self):
        kms = FakeClient(get_key_policy={"Policy": ORG_POLICY})
        auditor = make_auditor(kms=kms)
        auditor.check_key_policy("key-1", "first use")
        auditor.check_key_policy("key-1", "second use")
        self.assertEqual(len(auditor.findings), 1)
        self.assertEqual(len(kms.calls), 1)

    def test_access_denied_is_unchecked_not_a_pass(self):
        auditor = make_auditor(kms=FakeClient(get_key_policy=client_error("AccessDenied")))
        auditor.check_key_policy("key-1", "x")
        self.assertEqual(auditor.findings[0].severity, UNCHECKED)


class TestBucketPolicy(unittest.TestCase):
    def test_missing_policy_is_a_real_pass(self):
        auditor = make_auditor(
            s3=FakeClient(get_bucket_policy=client_error("NoSuchBucketPolicy"))
        )
        auditor.check_bucket_policy("logs", "session logs")
        self.assertEqual(auditor.findings, [])

    def test_access_denied_is_unchecked(self):
        auditor = make_auditor(s3=FakeClient(get_bucket_policy=client_error("AccessDenied")))
        auditor.check_bucket_policy("logs", "session logs")
        self.assertEqual(auditor.findings[0].severity, UNCHECKED)

    def test_org_condition_is_must_fix(self):
        auditor = make_auditor(s3=FakeClient(get_bucket_policy={"Policy": ORG_POLICY}))
        auditor.check_bucket_policy("logs", "session logs")
        self.assertEqual(auditor.findings[0].severity, MUST_FIX)
        self.assertEqual(auditor.findings[0].resource, "s3://logs")


class TestVpcEndpoints(unittest.TestCase):
    def _auditor(self, endpoints):
        return make_auditor(
            ec2=FakeClient(**{"paginate:describe_vpc_endpoints": [{"VpcEndpoints": endpoints}]})
        )

    def test_ssm_endpoint_with_org_condition_is_flagged(self):
        auditor = self._auditor(
            [
                {
                    "VpcEndpointId": "vpce-1",
                    "ServiceName": "com.amazonaws.eu-west-1.ssmmessages",
                    "PolicyDocument": ORG_POLICY,
                }
            ]
        )
        auditor.check_vpc_endpoints()
        self.assertEqual(len(auditor.findings), 1)
        self.assertEqual(auditor.findings[0].severity, MUST_FIX)

    def test_non_ssm_endpoint_is_ignored_even_when_org_pinned(self):
        """The audit is SSM-only: an org-pinned S3 endpoint is not our business."""
        auditor = self._auditor(
            [
                {
                    "VpcEndpointId": "vpce-2",
                    "ServiceName": "com.amazonaws.eu-west-1.s3",
                    "PolicyDocument": ORG_POLICY,
                }
            ]
        )
        auditor.check_vpc_endpoints()
        self.assertEqual(auditor.findings, [])

    def test_ssm_endpoint_without_org_condition_is_silent(self):
        auditor = self._auditor(
            [
                {
                    "VpcEndpointId": "vpce-3",
                    "ServiceName": "com.amazonaws.eu-west-1.ssm",
                    "PolicyDocument": CLEAN_POLICY,
                }
            ]
        )
        auditor.check_vpc_endpoints()
        self.assertEqual(auditor.findings, [])


class TestSecureStringKeys(unittest.TestCase):
    def test_groups_parameters_by_key_and_skips_aws_managed(self):
        params = [
            {"Name": "/app/db", "Type": "SecureString", "KeyId": "key-cmk"},
            {"Name": "/app/api", "Type": "SecureString", "KeyId": "key-cmk"},
            {"Name": "/app/plain", "Type": "String"},
            {"Name": "/app/default", "Type": "SecureString", "KeyId": "alias/aws/ssm"},
        ]
        kms = FakeClient(get_key_policy={"Policy": ORG_POLICY})
        auditor = make_auditor(
            ssm=FakeClient(**{"paginate:describe_parameters": [{"Parameters": params}]}),
            kms=kms,
        )
        auditor.check_securestring_keys()
        self.assertEqual(len(kms.calls), 1)  # one CMK, AWS-managed key skipped
        self.assertEqual(len(auditor.findings), 1)
        evidence = auditor.findings[0].evidence
        self.assertIn("2 SecureString parameter(s)", evidence)
        self.assertIn("/app/db", evidence)
        self.assertNotIn("/app/plain", evidence)


class TestResourceDataSync(unittest.TestCase):
    def test_org_source_is_flagged_and_destination_is_inspected(self):
        sync = {
            "SyncName": "central",
            "SyncSource": {
                "SourceType": "AwsOrganizations",
                "AwsOrganizationsSource": {
                    "OrganizationSourceType": "OrganizationalUnits",
                    "OrganizationalUnits": [{"OrganizationalUnitId": "ou-ab12-abcd1234"}],
                },
            },
            "S3Destination": {"BucketName": "inventory"},
        }
        auditor = make_auditor(
            ssm=FakeClient(**{"paginate:list_resource_data_sync": [{"ResourceDataSyncItems": [sync]}]}),
            s3=FakeClient(get_bucket_policy={"Policy": ORG_POLICY}),
        )
        auditor.check_resource_data_syncs()
        checks = {f.check for f in auditor.findings}
        self.assertIn("resource-data-sync", checks)
        self.assertIn("bucket-policy", checks)
        sync_finding = next(f for f in auditor.findings if f.check == "resource-data-sync")
        self.assertIn("AwsOrganizations", sync_finding.evidence)
        self.assertIn("ou-ab12-abcd1234", sync_finding.evidence)

    def test_plain_sync_with_clean_bucket_yields_nothing(self):
        sync = {"SyncName": "plain", "S3Destination": {"BucketName": "inventory"}}
        auditor = make_auditor(
            ssm=FakeClient(**{"paginate:list_resource_data_sync": [{"ResourceDataSyncItems": [sync]}]}),
            s3=FakeClient(get_bucket_policy={"Policy": CLEAN_POLICY}),
        )
        auditor.check_resource_data_syncs()
        self.assertEqual(auditor.findings, [])


class TestDelegatedAdministrator(unittest.TestCase):
    def _auditor(self, admin_id):
        return make_auditor(
            organizations=FakeClient(
                **{
                    "paginate:list_delegated_administrators": [
                        {"DelegatedAdministrators": [{"Id": admin_id}]}
                    ]
                }
            )
        )

    def test_flags_only_this_account(self):
        auditor = self._auditor("032851495384")
        auditor.check_delegated_administrator()
        self.assertEqual(len(auditor.findings), 1)
        self.assertEqual(auditor.findings[0].severity, MUST_FIX)

    def test_another_accounts_registration_is_not_our_problem(self):
        auditor = self._auditor("999988887777")
        auditor.check_delegated_administrator()
        self.assertEqual(auditor.findings, [])


class TestDocumentContent(unittest.TestCase):
    def test_flags_only_documents_pinned_to_the_org(self):
        contents = {
            "Pinned": '{"mainSteps":[{"inputs":{"TargetLocations":["ou-ab12-abcd1234"]}}]}',
            "Clean": '{"mainSteps":[{"inputs":{"InstanceIds":["i-123"]}}]}',
        }
        auditor = make_auditor(
            ssm=FakeClient(
                **{
                    "paginate:list_documents": [
                        {"DocumentIdentifiers": [{"Name": "Pinned"}, {"Name": "Clean"}]}
                    ],
                    "get_document": lambda Name: {"Content": contents[Name]},
                }
            )
        )
        auditor.check_document_content()
        self.assertEqual(auditor.document_count, 2)
        self.assertEqual(len(auditor.findings), 1)
        self.assertEqual(auditor.findings[0].resource, "document/Pinned")


class TestSessionManagerTargets(unittest.TestCase):
    def test_uncustomised_preferences_are_not_a_finding(self):
        auditor = make_auditor(ssm=FakeClient(get_document=client_error("InvalidDocument")))
        auditor.check_session_manager_targets()
        self.assertEqual(auditor.findings, [])

    def test_configured_bucket_and_key_are_inspected(self):
        content = '{"inputs":{"s3BucketName":"sessions","kmsKeyId":"key-cmk"}}'
        auditor = make_auditor(
            ssm=FakeClient(get_document={"Content": content}),
            s3=FakeClient(get_bucket_policy={"Policy": ORG_POLICY}),
            kms=FakeClient(get_key_policy={"Policy": ORG_POLICY}),
        )
        auditor.check_session_manager_targets()
        self.assertEqual({f.check for f in auditor.findings}, {"bucket-policy", "kms-key-policy"})


class TestRendering(unittest.TestCase):
    def test_md_escape_neutralises_table_breakers(self):
        self.assertEqual(md_escape("a|b\nc"), "a\\|b c")

    def test_report_states_a_clean_region_plainly(self):
        report = render_markdown([], {"account_id": "1"}, ["eu-west-1"])
        self.assertIn("## eu-west-1", report)
        self.assertIn("Nothing to fix.", report)

    def test_report_groups_by_region_not_severity(self):
        findings = [
            Finding(MUST_FIX, "kms-key-policy", "eu-west-1", "kms/key-1", "org id", "fix it"),
            Finding(MUST_FIX, "document-content", "us-east-1", "document/D", "ou id", "fix it"),
        ]
        report = render_markdown(findings, {"account_id": "1"}, ["eu-west-1", "us-east-1"])
        self.assertIn("## eu-west-1", report)
        self.assertIn("## us-east-1", report)
        self.assertNotIn("MUST-FIX", report)
        self.assertNotIn("Severity", report)
        # each finding lands under its own region heading
        west, east = report.split("## us-east-1")
        self.assertIn("kms/key-1", west)
        self.assertNotIn("kms/key-1", east)
        self.assertIn("document/D", east)

    def test_unreadable_resources_are_listed_separately_from_fixes(self):
        auditor = make_auditor(
            kms=FakeClient(get_key_policy={"Policy": ORG_POLICY}),
            s3=FakeClient(get_bucket_policy=client_error("AccessDenied")),
        )
        auditor.check_key_policy("key-1", "SecureString parameters")
        auditor.check_bucket_policy("logs", "session logs")
        report = render_markdown(auditor.findings, {"account_id": "1"}, ["eu-west-1"])
        self.assertIn("| Resource | What is wrong | Fix |", report)
        self.assertIn("### Could not be read", report)
        self.assertIn("| Items to fix | 1 |", report)

    def test_report_does_not_send_the_reader_elsewhere(self):
        findings = [
            Finding(MUST_FIX, "kms-key-policy", "eu-west-1", "kms/key-1", "org id", "fix it")
        ]
        report = render_markdown(findings, {"account_id": "1"}, ["eu-west-1"]).lower()
        for phrase in ("out of scope", "you may want", "consider checking", "check the"):
            self.assertNotIn(phrase, report)


if __name__ == "__main__":
    unittest.main()
