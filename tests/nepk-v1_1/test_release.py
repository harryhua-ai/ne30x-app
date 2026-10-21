from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package" / "vnext"))

from nepk_v1_1_pack import PackError, _load_production_key, canonical_json_sha256
from nepk_v1_1_release import (
    ReleaseError,
    GitHubReleaseClient,
    build_release_plan,
    publish_release,
    validate_environment_configuration,
    validate_release_request,
)
from nepk_v1_1_verify import verify_nepk
from test_nepk import pair_member, native_member, spki_for, ui_member


SOURCE = "a" * 40


class MemoryReleaseApi:
    simulation_only = True

    def __init__(self):
        self.tags = {}
        self.releases = {}
        self.asset_bytes = {}
        self.events = []
        self.fail_upload_number = None

    def get_tag(self, tag):
        return self.tags.get(tag)

    def tag_commit(self, reference):
        return reference["object"]["sha"] if reference else None

    def get_release_by_tag(self, tag):
        return self.releases.get(tag)

    def create_draft_release(self, plan):
        self.events.append(("create", plan["tag"]))
        release = {
            "id": len(self.releases) + 1,
            "tag_name": plan["tag"],
            "name": plan["title"],
            "body": plan["release_notes"],
            "draft": True,
            "assets": [],
        }
        self.tags[plan["tag"]] = {"object": {"sha": plan["source_sha"], "type": "commit"}}
        self.releases[plan["tag"]] = release
        return release

    def upload_asset(self, release, name, data):
        if self.fail_upload_number is not None and len([event for event in self.events if event[0] == "upload"]) + 1 == self.fail_upload_number:
            raise ReleaseError("injected partial upload")
        if any(item["name"] == name for item in release["assets"]):
            raise ReleaseError("asset already exists")
        asset_id = len(self.asset_bytes) + 1
        self.asset_bytes[asset_id] = data
        release["assets"].append({"id": asset_id, "name": name, "size": len(data)})
        self.events.append(("upload", name))

    def download_asset(self, asset):
        return self.asset_bytes[asset["id"]]

    def publish_release(self, release):
        release["draft"] = False
        self.events.append(("publish", release["tag_name"]))


class ReleasePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="nepk-release-test-")
        self.root = Path(self.temp.name)
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.spki = spki_for(self.key)
        self.publisher_id = "test-publisher"

    def tearDown(self):
        self.temp.cleanup()

    def make_app(self, app_id: str, sequence: int, *, native_version=(4, 0, 1), ui_version=(1, 0, 1), payload=b"native"):
        native = native_member(
            self.key,
            version=native_version,
            app_id=app_id,
            publisher_id=self.publisher_id,
            payload=payload,
        )
        ui = ui_member(
            self.key,
            native,
            version=ui_version,
            app_id=app_id,
            publisher_id=self.publisher_id,
            asset=f"<!doctype html><title>{app_id}</title>".encode(),
        )
        package = pair_member(native, ui, sequence, self.key)
        report = verify_nepk(package, {self.publisher_id: self.spki}, self.publisher_id, app_id)
        package_path = self.root / f"{app_id}-{sequence}.neapp"
        provenance_path = self.root / f"{app_id}-{sequence}.json"
        package_path.write_bytes(package)
        provenance_path.write_text(json.dumps({
            "artifact_type": "TEST ONLY simulation fixture",
            "publisher_id": self.publisher_id,
            "app_id": app_id,
            "publisher_spki_sha256": hashlib.sha256(self.spki).hexdigest(),
            "release_seq": sequence,
            "native_version": list(native_version),
            "ui_version": list(ui_version),
            "source": {"commit": SOURCE},
            "package": {"sha256": report["package_sha256"]},
        }, sort_keys=True) + "\n", encoding="utf-8")
        record = {
            "record_id": f"seq-{app_id}-{sequence}",
            "status": "authorized",
            "publisher_id": self.publisher_id,
            "app_id": app_id,
            "release_seq": sequence,
            "previous_high_water": 0,
            "source_sha": SOURCE,
            "native_tbs_sha256": report["native_tbs_sha256"],
            "ui_tbs_sha256": report["ui_tbs_sha256"],
            "pair_tbs_sha256": report["pair_tbs_sha256"],
            "package_sha256": report["package_sha256"],
            "publisher_spki_sha256": report["publisher_key_sha256"],
            "native_version": list(native_version),
            "ui_version": list(ui_version),
        }
        return {
            "request_app": {
                "app_id": app_id,
                "publisher_id": self.publisher_id,
                "release_seq": sequence,
                "native_version": ".".join(map(str, native_version)),
                "ui_version": ".".join(map(str, ui_version)),
                "sequence_record_id": record["record_id"],
                "compatibility": "NE301 Host v4; UI ABI 1",
            },
            "record": record,
            "package_path": package_path,
            "provenance_path": provenance_path,
            "report": report,
        }

    def make_request(self, apps, *, action="simulate", ledger_records=None, batch_version="1.2.3"):
        records = ledger_records if ledger_records is not None else [app["record"] for app in apps]
        ledger = {"version": 1, "records": records}
        request = {
            "version": 1,
            "action": action,
            "batch_version": batch_version,
            "source_sha": SOURCE,
            "authorization": {
                "request_id": "release-request-42",
                "authorization_ref": "https://example.com/authorization/42",
                "source_sha": SOURCE,
                "action": action,
            },
            "sequence_ledger": ledger,
            "apps": [app["request_app"] for app in apps],
        }
        return request, canonical_json_sha256(ledger)

    def build_plan(self, apps, request=None, ledger_sha=None):
        if request is None:
            request, ledger_sha = self.make_request(apps)
        return build_release_plan(
            request,
            {app["request_app"]["app_id"]: app["package_path"] for app in apps},
            {app["request_app"]["app_id"]: app["provenance_path"] for app in apps},
            {self.publisher_id: self.spki},
            {app["request_app"]["app_id"]: app["report"] for app in apps},
            expected_source_sha=SOURCE,
            expected_ledger_sha256=ledger_sha,
        )

    def test_environment_requires_reviewers_self_review_block_and_exact_main(self):
        environment = {
            "name": "production",
            "protection_rules": [{
                "type": "required_reviewers",
                "prevent_self_review": True,
                "reviewers": [{"type": "User", "reviewer": {"id": 10}}],
            }],
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        }
        policies = {"branch_policies": [{"name": "main", "type": "branch"}]}
        validate_environment_configuration(environment, policies)
        for changed_environment, changed_policies in (
            ({**environment, "protection_rules": []}, policies),
            ({**environment, "protection_rules": [{"type": "required_reviewers", "reviewers": [{"id": 10}], "prevent_self_review": False}]}, policies),
            (environment, {"branch_policies": [{"name": "main"}, {"name": "release/*"}]}),
            ({**environment, "name": "staging"}, policies),
        ):
            with self.subTest(environment=changed_environment, policies=changed_policies), self.assertRaises(ReleaseError):
                validate_environment_configuration(changed_environment, changed_policies)

    def test_request_requires_protected_ledger_source_and_authorized_seq(self):
        alpha = self.make_app("alpha", 7)
        request, ledger_sha = self.make_request([alpha], action="draft")
        validated = validate_release_request(request, expected_source_sha=SOURCE, expected_action="draft", expected_ledger_sha256=ledger_sha)
        self.assertEqual(validated["tag"], "v1.2.3")
        invalid_requests = []
        wrong_source = json.loads(json.dumps(request))
        wrong_source["source_sha"] = "b" * 40
        invalid_requests.append((wrong_source, ledger_sha))
        wrong_ledger = json.loads(json.dumps(request))
        wrong_ledger["sequence_ledger"]["records"][0]["release_seq"] = 8
        invalid_requests.append((wrong_ledger, ledger_sha))
        for invalid, pin in invalid_requests:
            with self.subTest(request=invalid), self.assertRaises(ReleaseError):
                validate_release_request(invalid, expected_source_sha=SOURCE, expected_ledger_sha256=pin)
        with self.assertRaises(ReleaseError):
            validate_release_request(request, expected_source_sha=SOURCE)
        secret_reference = json.loads(json.dumps(request))
        secret_reference["authorization"]["authorization_ref"] = "https://example.com/record?access_token=secret"
        with self.assertRaisesRegex(ReleaseError, "without credentials"):
            validate_release_request(secret_reference, expected_source_sha=SOURCE, expected_ledger_sha256=ledger_sha)

    def test_single_and_multiple_apps_produce_app_scoped_assets_and_notes(self):
        alpha = self.make_app("alpha", 7)
        beta = self.make_app("beta", 11)
        plan = self.build_plan([alpha, beta])
        self.assertEqual([app["asset_name"] for app in plan["apps"]], ["alpha-1.2.3.neapp", "beta-1.2.3.neapp"])
        self.assertIn("Native v4 version: `4.0.1`", plan["release_notes"])
        self.assertIn("NEUI v1 version: `1.0.1`", plan["release_notes"])
        self.assertIn("Pair release_seq: `7`", plan["release_notes"])
        self.assertIn("Publisher SPKI SHA-256:", plan["release_notes"])
        self.assertIn("Compatibility: NE301 Host v4; UI ABI 1", plan["release_notes"])
        self.assertIn("SIMULATION ONLY", plan["release_notes"])

    def test_duplicate_app_and_wrong_signed_app_fail_before_plan_creation(self):
        alpha = self.make_app("alpha", 7)
        duplicate = json.loads(json.dumps(alpha["request_app"]))
        request, ledger_sha = self.make_request([alpha])
        request["apps"].append(duplicate)
        with self.assertRaisesRegex(ReleaseError, "duplicate app_id"):
            validate_release_request(request, expected_source_sha=SOURCE, expected_ledger_sha256=ledger_sha)
        beta = self.make_app("beta", 3)
        request, ledger_sha = self.make_request([beta])
        with self.assertRaises(ReleaseError):
            build_release_plan(
                request,
                {"beta": alpha["package_path"]},
                {"beta": alpha["provenance_path"]},
                {self.publisher_id: self.spki},
                {"beta": alpha["report"]},
                expected_source_sha=SOURCE,
                expected_ledger_sha256=ledger_sha,
            )

    def test_known_test_publishers_cannot_create_production_release_plans(self):
        alpha = self.make_app("alpha", 7)
        request, ledger_sha = self.make_request([alpha], action="draft")
        with self.assertRaisesRegex(ReleaseError, "known TEST ONLY publishers"):
            self.build_plan([alpha], request, ledger_sha)

    def test_two_repeated_authorized_sequences_are_rejected(self):
        alpha = self.make_app("alpha", 7)
        repeated = dict(alpha["record"])
        repeated["record_id"] = "seq-alpha-7-reused"
        request, ledger_sha = self.make_request([alpha], ledger_records=[alpha["record"], repeated])
        with self.assertRaisesRegex(PackError, "reuses a publisher/app release_seq"):
            validate_release_request(request, expected_source_sha=SOURCE, expected_ledger_sha256=ledger_sha)

    def test_complete_simulated_publish_is_idempotent_and_never_overwrites_assets(self):
        alpha = self.make_app("alpha", 7)
        beta = self.make_app("beta", 11)
        plan = self.build_plan([alpha, beta])
        api = MemoryReleaseApi()
        draft = publish_release(plan, api, action="draft", authorized=False, simulation=True)
        first = publish_release(plan, api, action="publish", authorized=False, simulation=True)
        second = publish_release(plan, api, action="publish", authorized=False, simulation=True)
        self.assertEqual(draft["result"], "DRAFT_READY")
        self.assertEqual(first["result"], "PUBLISHED")
        self.assertEqual(second["result"], "IDEMPOTENT")
        self.assertEqual(len([event for event in api.events if event[0] == "upload"]), 2)
        self.assertEqual(len([event for event in api.events if event[0] == "publish"]), 1)
        original_assets = dict(api.asset_bytes)
        changed = self.make_app("alpha", 8, native_version=(4, 0, 2), payload=b"different")
        prior = dict(alpha["record"])
        prior["status"] = "signed"
        conflict, conflict_ledger_sha = self.make_request([changed], action="simulate", ledger_records=[prior, {
            **changed["record"], "previous_high_water": 7,
        }])
        conflict_plan = self.build_plan([changed], conflict, conflict_ledger_sha)
        with self.assertRaisesRegex(ReleaseError, "Release notes conflict"):
            publish_release(conflict_plan, api, action="publish", authorized=False, simulation=True)
        self.assertEqual(api.asset_bytes, original_assets)

    def test_draft_is_complete_before_publish_and_partial_assets_fail_closed(self):
        alpha = self.make_app("alpha", 7)
        beta = self.make_app("beta", 11)
        plan = self.build_plan([alpha, beta])
        api = MemoryReleaseApi()
        with self.assertRaisesRegex(ReleaseError, "requires an existing complete draft"):
            publish_release(plan, api, action="publish", authorized=False, simulation=True)
        self.assertEqual(api.events, [])
        result = publish_release(plan, api, action="draft", authorized=False, simulation=True)
        repeated_draft = publish_release(plan, api, action="draft", authorized=False, simulation=True)
        self.assertEqual(result["result"], "DRAFT_READY")
        self.assertEqual(repeated_draft["result"], "DRAFT_READY")
        self.assertTrue(api.get_release_by_tag(plan["tag"])["draft"])
        self.assertEqual(len([event for event in api.events if event[0] == "upload"]), 2)
        publish_release(plan, api, action="publish", authorized=False, simulation=True)
        self.assertFalse(api.get_release_by_tag(plan["tag"])["draft"])

        partial = MemoryReleaseApi()
        partial.fail_upload_number = 2
        with self.assertRaisesRegex(ReleaseError, "partial upload"):
            publish_release(plan, partial, action="draft", authorized=False, simulation=True)
        draft = partial.get_release_by_tag(plan["tag"])
        self.assertTrue(draft["draft"])
        self.assertEqual(len(draft["assets"]), 1)
        with self.assertRaisesRegex(ReleaseError, "partial asset set"):
            publish_release(plan, partial, action="publish", authorized=False, simulation=True)
        self.assertTrue(draft["draft"])

    def test_partial_public_release_and_preexisting_tag_are_never_modified(self):
        alpha = self.make_app("alpha", 7)
        plan = self.build_plan([alpha])
        api = MemoryReleaseApi()
        api.tags[plan["tag"]] = {"object": {"sha": SOURCE, "type": "commit"}}
        before = list(api.events)
        with self.assertRaisesRegex(ReleaseError, "without a matching Release"):
            publish_release(plan, api, action="publish", authorized=False, simulation=True)
        self.assertEqual(api.events, before)

        public = MemoryReleaseApi()
        publish_release(plan, public, action="draft", authorized=False, simulation=True)
        publish_release(plan, public, action="publish", authorized=False, simulation=True)
        release = public.get_release_by_tag(plan["tag"])
        prior_events = list(public.events)
        with self.assertRaisesRegex(ReleaseError, "already published"):
            publish_release(plan, public, action="draft", authorized=False, simulation=True)
        self.assertEqual(public.events, prior_events)
        release["assets"].clear()
        with self.assertRaisesRegex(ReleaseError, "published Release is incomplete"):
            publish_release(plan, public, action="publish", authorized=False, simulation=True)
        self.assertEqual(len([event for event in public.events if event[0] == "upload"]), 1)

    def test_unapproved_real_release_is_rejected_before_any_api_call(self):
        alpha = self.make_app("alpha", 7)
        plan = self.build_plan([alpha])
        plan["action"] = "draft"
        api = MemoryReleaseApi()
        with self.assertRaisesRegex(ReleaseError, "not authorized"):
            publish_release(plan, api, action="draft", authorized=False)
        self.assertEqual(api.events, [])

    def test_github_release_client_rejects_untrusted_upload_urls_and_asset_ids(self):
        client = GitHubReleaseClient("owner/repo", "token")
        with self.assertRaisesRegex(ReleaseError, "outside the expected GitHub endpoint"):
            client.upload_asset({
                "id": 1,
                "upload_url": "https://uploads.github.com.evil.example/repos/owner/repo/releases/1/assets{?name,label}",
            }, "line-crossing-1.2.3.neapp", b"fixture")
        with self.assertRaisesRegex(ReleaseError, "asset ID is malformed"):
            client.download_asset({"id": "not-an-integer"})

    def test_production_loader_rejects_test_spki(self):
        key_path = self.root / "test-key.pem"
        for scalar in (1, 2):
            public_test_key = ec.derive_private_key(scalar, ec.SECP256R1())
            key_path.write_bytes(public_test_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ))
            key_path.chmod(0o600)
            fingerprint = hashlib.sha256(spki_for(public_test_key)).hexdigest()
            with self.subTest(scalar=scalar), self.assertRaisesRegex(PackError, "TEST ONLY SPKI"):
                _load_production_key(key_path, fingerprint)

    def test_structural_preflight_is_explicitly_unpinned_and_wrong_action_fails(self):
        alpha = self.make_app("alpha", 7)
        request, ledger_sha = self.make_request([alpha], action="draft")
        request_path = self.root / "request.json"
        request_path.write_text(json.dumps(request), encoding="utf-8")
        command = [
            sys.executable,
            str(ROOT / "package" / "vnext" / "nepk_v1_1_release.py"),
            "preflight",
            "--request", str(request_path),
            "--source-sha", SOURCE,
            "--action", "draft",
            "--structural-only",
        ]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        self.assertEqual(json.loads(result.stdout)["ledger_validation"], "STRUCTURAL_ONLY")
        wrong_action = subprocess.run([
            sys.executable,
            str(ROOT / "package" / "vnext" / "nepk_v1_1_release.py"),
            "preflight",
            "--request", str(request_path),
            "--source-sha", SOURCE,
            "--action", "publish",
            "--structural-only",
        ], capture_output=True, text=True)
        self.assertNotEqual(wrong_action.returncode, 0)
        self.assertEqual(canonical_json_sha256(request["sequence_ledger"]), ledger_sha)


if __name__ == "__main__":
    unittest.main()
