#!/usr/bin/env python3
"""
Tests for arn_delete.py.

    python -m unittest -v test_arn_delete      # stdlib, no extra deps
    pytest test_arn_delete.py                  # also works if you have pytest

No AWS calls are made: the Cloud Control client is a scripted fake, so the tests
cover exactly the parsing/mapping/ordering/status logic that is easy to get wrong.
boto3 is stubbed out when it is not installed, so the suite runs anywhere.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import types
import unittest

# --------------------------------------------------------------------------- #
# Import the module under test, stubbing boto3 only if it is absent
# --------------------------------------------------------------------------- #

try:  # pragma: no cover - depends on the environment
    import boto3  # noqa: F401
    from botocore.exceptions import BotoCoreError, ClientError  # noqa: F401
except ImportError:  # pragma: no cover
    class ClientError(Exception):  # type: ignore[no-redef]
        # Mirrors botocore's real signature so tests read the same either way.
        def __init__(self, response, operation_name="Op"):
            super().__init__(str(response))
            self.response = response

    class BotoCoreError(Exception):  # type: ignore[no-redef]
        pass

    _boto3 = types.ModuleType("boto3")
    _boto3.Session = object
    _botocore = types.ModuleType("botocore")
    _exceptions = types.ModuleType("botocore.exceptions")
    _exceptions.ClientError = ClientError
    _exceptions.BotoCoreError = BotoCoreError
    sys.modules.update({"boto3": _boto3, "botocore": _botocore,
                        "botocore.exceptions": _exceptions})

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import arn_delete as ad  # noqa: E402


def client_error(code: str, msg: str = "boom") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": msg}}, "Op")


def target(arn: str) -> ad.Target:
    return ad.resolve(ad.parse_arn(arn))


# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class FakeCC:
    """Scripted Cloud Control client.

    delete_resource returns IN_PROGRESS `polls_needed` times before SUCCESS,
    unless the identifier contains a keyword that selects an error path.
    """

    def __init__(self, polls_needed: int = 0, final: str = "SUCCESS",
                 error_code: str | None = None):
        self.polls_needed = polls_needed
        self.final = final
        self.error_code = error_code
        self.polls = 0
        self.deleted: list[dict] = []
        self.probed: list[dict] = []

    def delete_resource(self, **kw):
        self.deleted.append(kw)
        ident = kw["Identifier"]
        if "gone" in ident:
            raise client_error("ResourceNotFoundException")
        if "unsup" in ident:
            raise client_error("UnsupportedActionException")
        if "denied" in ident:
            raise client_error("AccessDeniedException", "not allowed")
        status = "IN_PROGRESS" if self.polls_needed else self.final
        return {"ProgressEvent": {"RequestToken": "tok", "OperationStatus": status}}

    def get_resource_request_status(self, RequestToken):
        self.polls += 1
        done = self.polls >= self.polls_needed
        ev = {"RequestToken": RequestToken,
              "OperationStatus": self.final if done else "IN_PROGRESS"}
        if done and self.final == "FAILED":
            ev["ErrorCode"] = self.error_code or "GeneralServiceException"
            ev["StatusMessage"] = "could not delete"
        return {"ProgressEvent": ev}

    def get_resource(self, **kw):
        self.probed.append(kw)
        ident = kw["Identifier"]
        if "ghost" in ident:
            raise client_error("ResourceNotFoundException")
        if "broken" in ident:
            raise BotoCoreError()
        if "denied" in ident:
            raise client_error("AccessDeniedException", "nope")
        return {"ResourceDescription": {"Identifier": ident}}


class FakeSession:
    """Minimal boto3.Session stand-in that records every client it hands out."""

    def __init__(self, cc: FakeCC | None = None, region_name: str = "eu-west-1",
                 bucket_region: str | None = "eu-central-1"):
        self.cc = cc or FakeCC()
        self.region_name = region_name
        self.bucket_region = bucket_region
        self.clients: list[tuple[str, str | None]] = []
        self.hook_calls: list[tuple[str, dict]] = []
        self.location_calls = 0

    # -- boto3.Session API -------------------------------------------------- #

    def client(self, svc, region_name=None):
        self.clients.append((svc, region_name))
        if svc == "cloudcontrol":
            return self.cc
        return self._service_client(svc)

    def resource(self, svc, region_name=None):
        self.clients.append((f"{svc}-resource", region_name))
        rec = self.hook_calls

        class _Coll:
            def delete(self_inner):
                rec.append(("s3.delete_objects", {}))

        bucket = types.SimpleNamespace(object_versions=_Coll(), objects=_Coll())
        return types.SimpleNamespace(Bucket=lambda name: bucket)

    # -- helpers ------------------------------------------------------------ #

    def _service_client(self, svc):
        obj = types.SimpleNamespace()

        def recorder(name):
            def call(**kw):
                self.hook_calls.append((name, kw))
                if getattr(self, "hook_raises", None) == name:
                    raise client_error("InvalidParameterCombination")
            return call

        for name in ("modify_db_instance", "modify_db_cluster",
                     "modify_instance_attribute", "modify_load_balancer_attributes",
                     "delete_repository"):
            setattr(obj, name, recorder(name))

        def get_bucket_location(Bucket):
            self.location_calls += 1
            if self.bucket_region is None:
                raise client_error("AccessDenied")
            return {"LocationConstraint": self.bucket_region}

        obj.get_bucket_location = get_bucket_location
        return obj


# --------------------------------------------------------------------------- #
# ARN parsing
# --------------------------------------------------------------------------- #


class TestParseArn(unittest.TestCase):
    def test_slash_separated(self):
        a = ad.parse_arn("arn:aws:ec2:eu-central-1:111122223333:instance/i-0abc")
        self.assertEqual((a.service, a.region, a.account), ("ec2", "eu-central-1", "111122223333"))
        self.assertEqual((a.rtype, a.rid), ("instance", "i-0abc"))

    def test_colon_separated(self):
        a = ad.parse_arn("arn:aws:lambda:eu-west-1:1:function:my-fn")
        self.assertEqual((a.rtype, a.rid), ("function", "my-fn"))

    def test_no_type_segment(self):
        a = ad.parse_arn("arn:aws:s3:::my-bucket")
        self.assertEqual((a.rtype, a.rid, a.rest), ("", "my-bucket", "my-bucket"))

    def test_earliest_separator_wins(self):
        # The regression that made log groups parse as type "log-group:".
        a = ad.parse_arn("arn:aws:logs:eu-west-1:1:log-group:/aws/lambda/fn:*")
        self.assertEqual(a.rtype, "log-group")
        self.assertEqual(a.rid, "/aws/lambda/fn:*")

    def test_leading_slash_is_not_a_separator(self):
        a = ad.parse_arn("arn:aws:apigateway:us-east-1::/restapis/abc123")
        self.assertEqual((a.rtype, a.rid), ("restapis", "abc123"))

    def test_whitespace_is_trimmed(self):
        a = ad.parse_arn("  arn:aws:s3:::b  ")
        self.assertEqual(a.raw, "arn:aws:s3:::b")

    def test_rejects_malformed(self):
        for bad in ("not-an-arn", "", "arn:aws:ec2", "aws:ec2:r:a:instance/i-1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                ad.parse_arn(bad)


# --------------------------------------------------------------------------- #
# Mapping / identifier extraction
# --------------------------------------------------------------------------- #


class TestResolve(unittest.TestCase):
    def test_identifier_shapes(self):
        cases = {
            "arn:aws:ec2:eu-west-1:1:instance/i-0abc":
                ("AWS::EC2::Instance", "i-0abc"),
            "arn:aws:rds:eu-west-1:1:db:prod-db":
                ("AWS::RDS::DBInstance", "prod-db"),
            "arn:aws:s3:::my-bucket":
                ("AWS::S3::Bucket", "my-bucket"),
            # SQS needs a queue URL, not the ARN
            "arn:aws:sqs:eu-west-1:111122223333:my-queue":
                ("AWS::SQS::Queue",
                 "https://sqs.eu-west-1.amazonaws.com/111122223333/my-queue"),
            # SNS needs the full ARN
            "arn:aws:sns:eu-west-1:1:my-topic":
                ("AWS::SNS::Topic", "arn:aws:sns:eu-west-1:1:my-topic"),
            # IAM path must be stripped down to the role name
            "arn:aws:iam::1:role/service-role/deep/MyRole":
                ("AWS::IAM::Role", "MyRole"),
            # trailing ":*" must go
            "arn:aws:logs:eu-west-1:1:log-group:/aws/lambda/fn:*":
                ("AWS::Logs::LogGroup", "/aws/lambda/fn"),
            "arn:aws:logs:eu-west-1:1:log-group:/aws/lambda/fn":
                ("AWS::Logs::LogGroup", "/aws/lambda/fn"),
            # composite keys
            "arn:aws:ecs:eu-west-1:1:service/prod-cluster/api":
                ("AWS::ECS::Service", "prod-cluster|api"),
            "arn:aws:eks:eu-west-1:1:nodegroup/prod/ng-1/uuid-123":
                ("AWS::EKS::Nodegroup", "prod|ng-1"),
            # hierarchical SSM names keep their leading slash
            "arn:aws:ssm:eu-west-1:1:parameter/app/prod/key":
                ("AWS::SSM::Parameter", "/app/prod/key"),
            "arn:aws:ssm:eu-west-1:1:parameter/FlatName":
                ("AWS::SSM::Parameter", "FlatName"),
            "arn:aws:apigateway:us-east-1::/restapis/abc123":
                ("AWS::ApiGateway::RestApi", "abc123"),
            "arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/my-alb/50dc":
                ("AWS::ElasticLoadBalancingV2::LoadBalancer",
                 "arn:aws:elasticloadbalancing:eu-west-1:1:loadbalancer/app/my-alb/50dc"),
        }
        for arn, (type_name, identifier) in cases.items():
            with self.subTest(arn=arn):
                t = target(arn)
                self.assertEqual(t.type_name, type_name)
                self.assertEqual(t.identifier, identifier)

    def test_unknown_service_is_rejected(self):
        with self.assertRaises(KeyError):
            target("arn:aws:elasticbeanstalk:eu-west-1:1:environment/x/y")

    def test_s3_object_arn_is_not_widened_to_its_bucket(self):
        # The dangerous case: must never resolve to a bucket deletion.
        with self.assertRaises(ValueError):
            target("arn:aws:s3:::my-bucket/some/key.txt")

    def test_log_stream_arn_is_not_widened_to_its_group(self):
        with self.assertRaises(ValueError):
            target("arn:aws:logs:eu-west-1:1:log-group:/g:log-stream:s")

    def test_every_mapping_entry_is_well_formed(self):
        for key, (type_name, extractor, order) in ad.MAPPING.items():
            with self.subTest(key=key):
                self.assertIsInstance(key, tuple)
                self.assertTrue(type_name.startswith("AWS::"))
                self.assertTrue(callable(extractor))
                self.assertIsInstance(order, int)


# --------------------------------------------------------------------------- #
# build_targets: dedup + ordering
# --------------------------------------------------------------------------- #


class TestBuildTargets(unittest.TestCase):
    def test_dependencies_are_deleted_last(self):
        targets, problems = ad.build_targets([
            "arn:aws:ec2:eu-west-1:1:vpc/vpc-1",
            "arn:aws:logs:eu-west-1:1:log-group:/g",
            "arn:aws:ec2:eu-west-1:1:security-group/sg-1",
            "arn:aws:ec2:eu-west-1:1:instance/i-1",
        ])
        self.assertEqual([t.identifier for t in targets],
                         ["i-1", "sg-1", "vpc-1", "/g"])
        self.assertEqual(problems, [])

    def test_duplicates_collapse(self):
        targets, _ = ad.build_targets(["arn:aws:s3:::b"] * 3)
        self.assertEqual(len(targets), 1)

    def test_bad_arns_are_collected_not_raised(self):
        targets, problems = ad.build_targets([
            "arn:aws:ec2:eu-west-1:1:instance/i-1",
            "junk",
            "arn:aws:s3:::bucket/key",
        ])
        self.assertEqual(len(targets), 1)
        self.assertEqual([p[0] for p in problems], ["junk", "arn:aws:s3:::bucket/key"])


# --------------------------------------------------------------------------- #
# Input formats
# --------------------------------------------------------------------------- #


class TestReadArns(unittest.TestCase):
    def _write(self, text: str) -> str:
        fh = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        fh.write(text)
        fh.close()
        self.addCleanup(os.unlink, fh.name)
        return fh.name

    def test_flat_file_with_comments_and_blanks(self):
        path = self._write(
            "# header\n"
            "arn:aws:s3:::a\n"
            "\n"
            "  arn:aws:s3:::b  # keep\n"
            "   \n"
        )
        self.assertEqual(ad.read_arns(path, []), ["arn:aws:s3:::a", "arn:aws:s3:::b"])

    def test_json_list_of_strings(self):
        path = self._write(json.dumps(["arn:aws:s3:::a", "arn:aws:s3:::b"]))
        self.assertEqual(ad.read_arns(path, []), ["arn:aws:s3:::a", "arn:aws:s3:::b"])

    def test_tagging_api_output(self):
        path = self._write(json.dumps({"ResourceTagMappingList": [
            {"ResourceARN": "arn:aws:s3:::a", "Tags": [{"Key": "env", "Value": "dev"}]},
            {"ResourceARN": "arn:aws:s3:::b", "Tags": []},
        ]}))
        self.assertEqual(ad.read_arns(path, []), ["arn:aws:s3:::a", "arn:aws:s3:::b"])

    def test_inline_arns_combine_with_file(self):
        path = self._write("arn:aws:s3:::from-file\n")
        self.assertEqual(ad.read_arns(path, ["arn:aws:s3:::inline"]),
                         ["arn:aws:s3:::inline", "arn:aws:s3:::from-file"])

    def test_stdin(self):
        orig, sys.stdin = sys.stdin, io.StringIO("arn:aws:s3:::a\n# c\n")
        self.addCleanup(lambda: setattr(sys, "stdin", orig))
        self.assertEqual(ad.read_arns("-", []), ["arn:aws:s3:::a"])

    def test_unrecognized_json_shape_raises(self):
        path = self._write(json.dumps({"Nope": [1, 2]}))
        with self.assertRaises(ValueError):
            ad.read_arns(path, [])

    def test_missing_file_raises_oserror(self):
        with self.assertRaises(OSError):
            ad.read_arns("/nonexistent/nope.txt", [])


# --------------------------------------------------------------------------- #
# Region resolution
# --------------------------------------------------------------------------- #


class TestRegionFor(unittest.TestCase):
    def test_arn_region_wins(self):
        sess = FakeSession()
        d = ad.Deleter(sess)
        self.assertEqual(d.region_for(target("arn:aws:ec2:ap-south-1:1:instance/i-1")),
                         "ap-south-1")
        self.assertEqual(sess.location_calls, 0)

    def test_bucket_region_is_looked_up_not_guessed(self):
        sess = FakeSession(region_name="eu-west-1", bucket_region="eu-central-1")
        d = ad.Deleter(sess)
        self.assertEqual(d.region_for(target("arn:aws:s3:::b")), "eu-central-1")

    def test_us_east_1_bucket_reports_a_real_region(self):
        # GetBucketLocation returns "" (or None) for us-east-1.
        sess = FakeSession(bucket_region="")
        d = ad.Deleter(sess)
        self.assertEqual(d.region_for(target("arn:aws:s3:::b")), "us-east-1")

    def test_bucket_region_is_cached(self):
        sess = FakeSession()
        d = ad.Deleter(sess)
        t = target("arn:aws:s3:::b")
        d.region_for(t)
        d.region_for(t)
        self.assertEqual(sess.location_calls, 1)

    def test_failed_lookup_falls_back_without_raising(self):
        sess = FakeSession(bucket_region=None, region_name="eu-west-1")
        d = ad.Deleter(sess)
        self.assertEqual(d.region_for(target("arn:aws:s3:::b")), "eu-west-1")

    def test_global_arn_uses_session_region(self):
        d = ad.Deleter(FakeSession(region_name="eu-west-1"))
        self.assertEqual(d.region_for(target("arn:aws:iam::1:role/R")), "eu-west-1")


# --------------------------------------------------------------------------- #
# exists() / delete()
# --------------------------------------------------------------------------- #


class TestExists(unittest.TestCase):
    def test_hit_and_miss(self):
        d = ad.Deleter(FakeSession())
        self.assertEqual(d.exists(target("arn:aws:ec2:eu-west-1:1:instance/i-live")),
                         (True, "exists"))
        self.assertEqual(d.exists(target("arn:aws:ec2:eu-west-1:1:instance/i-ghost")),
                         (False, "not found"))

    def test_permission_error_is_reported_distinctly(self):
        d = ad.Deleter(FakeSession())
        ok, why = d.exists(target("arn:aws:ec2:eu-west-1:1:instance/i-denied"))
        self.assertFalse(ok)
        self.assertIn("AccessDeniedException", why)

    def test_transport_error_does_not_propagate(self):
        d = ad.Deleter(FakeSession())
        ok, why = d.exists(target("arn:aws:ec2:eu-west-1:1:instance/i-broken"))
        self.assertFalse(ok)
        self.assertIn("probe failed", why)


class TestDelete(unittest.TestCase):
    def setUp(self):
        # No real waiting in _wait().
        self._sleep, ad.time.sleep = ad.time.sleep, lambda s: None
        self.addCleanup(lambda: setattr(ad.time, "sleep", self._sleep))

    def test_success_after_polling(self):
        cc = FakeCC(polls_needed=3)
        d = ad.Deleter(FakeSession(cc))
        self.assertEqual(d.delete(target("arn:aws:ec2:eu-west-1:1:instance/i-1")),
                         ("DELETED", "ok"))
        self.assertEqual(cc.polls, 3)

    def test_already_gone_is_skipped_not_failed(self):
        d = ad.Deleter(FakeSession())
        status, _ = d.delete(target("arn:aws:ec2:eu-west-1:1:instance/i-gone"))
        self.assertEqual(status, "SKIPPED")

    def test_unsupported_type(self):
        d = ad.Deleter(FakeSession())
        status, msg = d.delete(target("arn:aws:ec2:eu-west-1:1:instance/i-unsup"))
        self.assertEqual(status, "UNSUPPORTED")
        self.assertIn("AWS::EC2::Instance", msg)

    def test_other_client_error_is_an_error(self):
        d = ad.Deleter(FakeSession())
        status, msg = d.delete(target("arn:aws:ec2:eu-west-1:1:instance/i-denied"))
        self.assertEqual(status, "ERROR")
        self.assertIn("AccessDeniedException", msg)

    def test_failed_progress_event(self):
        cc = FakeCC(polls_needed=1, final="FAILED", error_code="InvalidRequest")
        d = ad.Deleter(FakeSession(cc))
        status, msg = d.delete(target("arn:aws:ec2:eu-west-1:1:instance/i-1"))
        self.assertEqual(status, "FAILED")
        self.assertIn("InvalidRequest", msg)

    def test_not_found_progress_event_is_skipped(self):
        cc = FakeCC(polls_needed=1, final="FAILED", error_code="NotFound")
        d = ad.Deleter(FakeSession(cc))
        status, _ = d.delete(target("arn:aws:ec2:eu-west-1:1:instance/i-1"))
        self.assertEqual(status, "SKIPPED")

    def test_timeout_reports_the_request_token(self):
        cc = FakeCC(polls_needed=99)
        d = ad.Deleter(FakeSession(cc), timeout=0)
        status, msg = d.delete(target("arn:aws:ec2:eu-west-1:1:instance/i-1"))
        self.assertEqual(status, "TIMEOUT")
        self.assertIn("tok", msg)

    def test_call_lands_in_the_resolved_region_not_the_session_default(self):
        sess = FakeSession(region_name="eu-west-1", bucket_region="ap-south-1")
        d = ad.Deleter(sess)
        d.delete(target("arn:aws:s3:::b"))
        self.assertIn(("cloudcontrol", "ap-south-1"), sess.clients)

    def test_role_arn_is_forwarded(self):
        sess = FakeSession()
        d = ad.Deleter(sess, role_arn="arn:aws:iam::1:role/Deleter")
        d.delete(target("arn:aws:ec2:eu-west-1:1:instance/i-1"))
        self.assertEqual(sess.cc.deleted[0]["RoleArn"], "arn:aws:iam::1:role/Deleter")


# --------------------------------------------------------------------------- #
# Pre-hooks
# --------------------------------------------------------------------------- #


class TestPreHooks(unittest.TestCase):
    def setUp(self):
        self._sleep, ad.time.sleep = ad.time.sleep, lambda s: None
        self.addCleanup(lambda: setattr(ad.time, "sleep", self._sleep))

    def test_hooks_do_not_run_without_force(self):
        sess = FakeSession()
        ad.Deleter(sess, force=False).delete(target("arn:aws:rds:eu-west-1:1:db:d"))
        self.assertEqual(sess.hook_calls, [])

    def test_rds_deletion_protection_is_stripped_first(self):
        sess = FakeSession()
        ad.Deleter(sess, force=True).delete(target("arn:aws:rds:eu-west-1:1:db:d"))
        names = [c[0] for c in sess.hook_calls]
        self.assertEqual(names, ["modify_db_instance"])
        self.assertIs(sess.hook_calls[0][1]["DeletionProtection"], False)
        self.assertEqual(len(sess.cc.deleted), 1)  # still deleted afterwards

    def test_s3_bucket_is_emptied_in_its_own_region(self):
        sess = FakeSession(bucket_region="ap-south-1")
        ad.Deleter(sess, force=True).delete(target("arn:aws:s3:::b"))
        self.assertIn(("s3-resource", "ap-south-1"), sess.clients)
        self.assertEqual([c[0] for c in sess.hook_calls],
                         ["s3.delete_objects", "s3.delete_objects"])

    def test_ecr_hook_short_circuits_cloud_control(self):
        sess = FakeSession()
        status, msg = ad.Deleter(sess, force=True).delete(
            target("arn:aws:ecr:eu-west-1:1:repository/my-repo"))
        self.assertEqual(status, "DELETED")
        self.assertIn("pre-hook", msg)
        self.assertEqual(sess.cc.deleted, [])  # never reached Cloud Control

    def test_failing_hook_still_attempts_the_delete(self):
        sess = FakeSession()
        sess.hook_raises = "modify_db_instance"
        with contextlib.redirect_stdout(io.StringIO()) as buf:  # hook prints a warning
            status, _ = ad.Deleter(sess, force=True).delete(
                target("arn:aws:rds:eu-west-1:1:db:d"))
        self.assertEqual(status, "DELETED")
        self.assertEqual(len(sess.cc.deleted), 1)
        self.assertIn("pre-hook warning", buf.getvalue())

    def test_every_hook_accepts_the_documented_signature(self):
        for type_name, hook in ad.PRE_HOOKS.items():
            with self.subTest(type_name=type_name):
                self.assertEqual(hook.__code__.co_argcount, 3)


# --------------------------------------------------------------------------- #
# Dry run / execute / grace period
# --------------------------------------------------------------------------- #


class _Captured(unittest.TestCase):
    def capture(self, fn, *a, **kw):
        buf, orig = io.StringIO(), sys.stdout
        sys.stdout = buf
        try:
            rc = fn(*a, **kw)
        finally:
            sys.stdout = orig
        return rc, buf.getvalue()


class TestDryRun(_Captured):
    def test_dry_run_touches_nothing_and_lists_everything(self):
        targets, problems = ad.build_targets([
            "arn:aws:ec2:eu-west-1:1:instance/i-1", "junk"])
        rc, out = self.capture(ad.dry_run, targets, problems)
        self.assertEqual(rc, 1)  # unrecognized ARN present
        self.assertIn("DRY RUN", out)
        self.assertIn("i-1", out)
        self.assertIn("UNRECOGNIZED ARN: junk", out)
        self.assertIn("--execute", out)

    def test_clean_dry_run_exits_zero(self):
        targets, problems = ad.build_targets(["arn:aws:ec2:eu-west-1:1:instance/i-1"])
        rc, _ = self.capture(ad.dry_run, targets, problems)
        self.assertEqual(rc, 0)

    def test_check_mode_probes_and_reports_existence(self):
        sess = FakeSession()
        d = ad.Deleter(sess)
        targets, problems = ad.build_targets([
            "arn:aws:ec2:eu-west-1:1:instance/i-live",
            "arn:aws:ec2:eu-west-1:1:instance/i-ghost"])
        _, out = self.capture(ad.dry_run, targets, problems, d)
        self.assertIn("[exists]", out)
        self.assertIn("[not found]", out)
        self.assertIn("unreachable/not found: 1", out)
        self.assertEqual(len(sess.cc.probed), 2)
        self.assertEqual(sess.cc.deleted, [])


class TestBlastRadius(_Captured):
    def test_multiple_accounts_are_flagged(self):
        targets, _ = ad.build_targets([
            "arn:aws:ec2:eu-west-1:111122223333:instance/i-1",
            "arn:aws:ec2:eu-west-1:999988887777:instance/i-2"])
        _, out = self.capture(ad.print_blast_radius, targets)
        self.assertIn("111122223333", out)
        self.assertIn("999988887777", out)
        self.assertIn("WARNING", out)

    def test_single_account_is_not_flagged(self):
        targets, _ = ad.build_targets([
            "arn:aws:ec2:eu-west-1:111122223333:instance/i-1",
            "arn:aws:ec2:eu-west-1:111122223333:instance/i-2"])
        _, out = self.capture(ad.print_blast_radius, targets)
        self.assertNotIn("WARNING", out)


class TestGracePeriod(_Captured):
    def test_countdown_completes(self):
        orig, ad.time.sleep = ad.time.sleep, lambda s: None
        self.addCleanup(lambda: setattr(ad.time, "sleep", orig))
        rc, out = self.capture(ad.grace_period, 3)
        self.assertTrue(rc)
        self.assertIn("Ctrl-C", out)

    def test_ctrl_c_aborts(self):
        def boom(_):
            raise KeyboardInterrupt
        orig, ad.time.sleep = ad.time.sleep, boom
        self.addCleanup(lambda: setattr(ad.time, "sleep", orig))
        rc, out = self.capture(ad.grace_period, 3)
        self.assertFalse(rc)
        self.assertIn("nothing was deleted", out)


class TestExecute(_Captured):
    def setUp(self):
        self._sleep, ad.time.sleep = ad.time.sleep, lambda s: None
        self.addCleanup(lambda: setattr(ad.time, "sleep", self._sleep))

    def test_plan_is_printed_before_anything_is_deleted(self):
        sess = FakeSession()
        targets, problems = ad.build_targets([
            "arn:aws:ec2:eu-west-1:1:instance/i-1",
            "arn:aws:ec2:eu-west-1:1:vpc/vpc-1"])
        rc, out = self.capture(ad.execute, targets, problems,
                               ad.Deleter(sess), grace=0)
        self.assertEqual(rc, 0)
        self.assertLess(out.index("ABOUT TO DELETE"), out.index("[1/2]"))
        self.assertIn("IRREVERSIBLE", out)
        self.assertEqual(len(sess.cc.deleted), 2)

    def test_execute_does_not_probe_every_target(self):
        sess = FakeSession()
        targets, _ = ad.build_targets(["arn:aws:ec2:eu-west-1:1:instance/i-1"])
        self.capture(ad.execute, targets, [], ad.Deleter(sess), grace=0)
        self.assertEqual(sess.cc.probed, [])

    def test_ctrl_c_during_grace_deletes_nothing(self):
        def boom(_):
            raise KeyboardInterrupt
        ad.time.sleep = boom
        sess = FakeSession()
        targets, _ = ad.build_targets(["arn:aws:ec2:eu-west-1:1:instance/i-1"])
        rc, out = self.capture(ad.execute, targets, [], ad.Deleter(sess), grace=5)
        self.assertEqual(rc, 130)
        self.assertEqual(sess.cc.deleted, [])
        self.assertIn("nothing was deleted", out)

    def test_unrecognized_arns_make_the_run_exit_nonzero(self):
        sess = FakeSession()
        targets, problems = ad.build_targets([
            "arn:aws:ec2:eu-west-1:1:instance/i-1", "junk"])
        rc, out = self.capture(ad.execute, targets, problems,
                               ad.Deleter(sess), grace=0)
        self.assertEqual(rc, 1)
        self.assertIn("will be SKIPPED", out)
        self.assertEqual(len(sess.cc.deleted), 1)  # the good one still went

    def test_failures_are_summarized(self):
        cc = FakeCC(polls_needed=1, final="FAILED", error_code="Boom")
        targets, _ = ad.build_targets(["arn:aws:ec2:eu-west-1:1:instance/i-1"])
        rc, out = self.capture(ad.execute, targets, [],
                               ad.Deleter(FakeSession(cc)), grace=0)
        self.assertEqual(rc, 1)
        self.assertIn("FAILED", out)
        self.assertIn("failures: 1", out)

    def test_nothing_to_delete(self):
        rc, out = self.capture(ad.execute, [], [], ad.Deleter(FakeSession()), grace=0)
        self.assertEqual(rc, 0)
        self.assertIn("Nothing to delete", out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
