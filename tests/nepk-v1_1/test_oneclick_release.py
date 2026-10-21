from __future__ import annotations

import copy
import hashlib
import inspect
import json
import sys
import unittest
import tempfile

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package" / "vnext"))
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "tests" / "nepk-v1_1"))

import nepk_v1_1_release as release
from nepk_v1_1_release import ReleaseError
from test_release import MemoryReleaseApi, ReleasePipelineTests


PUBLISHER = "production-publisher"
APP = "line-crossing"
SPKI_SHA256 = "a" * 64
GENESIS_SHA256 = "b" * 64
SOURCE = "a" * 40


class MemoryLedgerRef:
    def __init__(self, ledger=None):
        self.ledger = copy.deepcopy(ledger)
        self.head_sha = "head-0" if ledger is not None else None
        self.revisions = []
        self.before_next_cas = None

    def read_sequence_ledger(self):
        if self.ledger is None:
            return None
        return self.head_sha, copy.deepcopy(self.ledger)

    def create_initial_sequence_ledger(self, ledger):
        if self.ledger is not None:
            raise ReleaseError("sequence ledger ref already exists")
        self.ledger = copy.deepcopy(ledger)
        self.head_sha = "genesis-head"
        self.revisions.append(copy.deepcopy(ledger))
        return self.head_sha

    def compare_and_swap_sequence_ledger(self, expected_head_sha, ledger):
        if self.before_next_cas is not None:
            callback = self.before_next_cas
            self.before_next_cas = None
            callback()
        if expected_head_sha != self.head_sha:
            return False
        self.ledger = copy.deepcopy(ledger)
        self.head_sha = f"head-{len(self.revisions) + 1}"
        self.revisions.append(copy.deepcopy(ledger))
        return True


class MemoryOneClickApi(MemoryReleaseApi):
    def __init__(self):
        super().__init__()
        self.fail_publish_once = False

    def create_tag(self, tag, source_sha):
        if tag in self.tags:
            raise ReleaseError("tag already exists")
        self.tags[tag] = {"object": {"sha": source_sha, "type": "commit"}}
        self.events.append(("tag", tag))

    def create_draft_release(self, plan):
        if plan["tag"] not in self.tags:
            raise ReleaseError("release tag was not created")
        release = {
            "id": len(self.releases) + 1,
            "tag_name": plan["tag"],
            "name": plan["title"],
            "body": plan["release_notes"],
            "html_url": f"https://github.com/example/repo/releases/tag/{plan['tag']}",
            "draft": True,
            "prerelease": False,
            "assets": [],
        }
        self.releases[plan["tag"]] = release
        self.events.append(("create", plan["tag"]))
        return release

    def publish_release(self, release_data):
        if self.fail_publish_once:
            self.fail_publish_once = False
            raise ReleaseError("injected publish failure")
        super().publish_release(release_data)


class OneClickReleaseTests(unittest.TestCase):
    def setUp(self):
        self.fixture = ReleasePipelineTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)

    def make_app(self, sequence=7, payload=b"native", native_version=(4, 0, 1), ui_version=(1, 0, 1)):
        return self.fixture.make_app(APP, sequence, payload=payload, native_version=native_version, ui_version=ui_version)

    def make_plan(self, app, *, action="simulate", ledger_records=None):
        request, ledger_sha = self.fixture.make_request(
            [app], action=action, ledger_records=ledger_records, batch_version="1.0.0"
        )
        return self.fixture.build_plan([app], request, ledger_sha)

    def required_api(self, name):
        function = getattr(release, name, None)
        self.assertTrue(callable(function), f"release module must implement {name}")
        return function

    def test_first_release_uses_protected_genesis_proof_and_allocates_seq_one(self):
        initialize = self.required_api("initialize_sequence_ledger")
        initialize_ref = self.required_api("initialize_sequence_ledger_ref")
        reserve = self.required_api("reserve_release_sequence")
        validate = self.required_api("validate_sequence_ledger")
        ledger = initialize(PUBLISHER, APP, SPKI_SHA256)
        genesis_digest = ledger["events"][0]["digest"]
        self.assertEqual(genesis_digest, hashlib.sha256(json.dumps({
            "kind": "genesis",
            "version": 1,
            "publisher_id": PUBLISHER,
            "app_id": APP,
            "publisher_spki_sha256": SPKI_SHA256,
            "release_seq": 0,
            "previous_digest": "0" * 64,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        client = MemoryLedgerRef()
        with self.assertRaisesRegex(ReleaseError, "does not match the protected genesis fingerprint"):
            initialize_ref(client, ledger, "f" * 64, PUBLISHER, APP, SPKI_SHA256)
        initialize_ref(client, ledger, genesis_digest, PUBLISHER, APP, SPKI_SHA256)
        with self.assertRaisesRegex(ReleaseError, "already exists"):
            initialize_ref(client, ledger, genesis_digest, PUBLISHER, APP, SPKI_SHA256)
        validate(ledger, genesis_digest, PUBLISHER, APP, SPKI_SHA256)
        reservation = reserve(
            client,
            genesis_sha256=genesis_digest,
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            batch_version="1.0.0",
            source_sha=SOURCE,
            build_input_sha256="c" * 64,
            run_id="100",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/100",
        )
        self.assertEqual(reservation["release_seq"], 1)
        self.assertEqual(reservation["previous_digest"], genesis_digest)
        self.assertEqual(client.ledger["events"][-1]["run_url"], "https://github.com/example/repo/actions/runs/100")

    def test_dispatch_version_requires_one_canonical_semantic_version(self):
        parse_version = self.required_api("parse_dispatch_version")
        self.assertEqual(parse_version("v1.0.0"), "1.0.0")
        for invalid in ("1.0.0", "v01.0.0", "v1.0", "v1.0.0-rc1", "v1.0.0.1", " v1.0.0"):
            with self.subTest(version=invalid), self.assertRaises(ReleaseError):
                parse_version(invalid)

    def test_native_and_ui_versions_are_read_from_packaging_sources(self):
        import nepk_v1_1_production_release as production_release

        read_versions = getattr(production_release, "read_line_crossing_versions", None)
        self.assertTrue(callable(read_versions), "production release must derive versions from source files")
        self.assertEqual(read_versions(ROOT), ("4.0.0", "1.0.0"))

    def test_one_time_admin_initialization_requires_the_pinned_genesis_fingerprint(self):
        import nepk_v1_1_production_release as production_release

        initialize = getattr(production_release, "initialize_production_sequence_ledger", None)
        self.assertTrue(callable(initialize), "production release must provide a one-time ledger initializer")
        genesis = {
            "kind": "genesis",
            "version": 1,
            "publisher_id": PUBLISHER,
            "app_id": APP,
            "publisher_spki_sha256": SPKI_SHA256,
            "release_seq": 0,
            "previous_digest": "0" * 64,
        }
        expected = hashlib.sha256(json.dumps(genesis, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        client = MemoryLedgerRef()
        with self.assertRaisesRegex(ReleaseError, "does not match the protected genesis fingerprint"):
            initialize(client, PUBLISHER, APP, SPKI_SHA256, "f" * 64)
        self.assertIsNone(client.ledger)
        result = initialize(client, PUBLISHER, APP, SPKI_SHA256, expected)
        self.assertEqual(result["genesis_sha256"], expected)
        self.assertEqual(client.ledger["events"][0]["digest"], expected)

    def test_missing_signing_secret_and_uninitialized_ledger_fail_closed(self):
        reserve = self.required_api("reserve_release_sequence")
        with self.assertRaisesRegex(ReleaseError, "one-time administrator ledger initialization"):
            reserve(
                MemoryLedgerRef(),
                genesis_sha256=GENESIS_SHA256,
                publisher_id=PUBLISHER,
                app_id=APP,
                publisher_spki_sha256=SPKI_SHA256,
                batch_version="1.0.0",
                source_sha=SOURCE,
                build_input_sha256="c" * 64,
                run_id="101",
                run_attempt=1,
                run_url="https://github.com/example/repo/actions/runs/101",
            )
        import nepk_v1_1_production_release as production_release
        validate_signing_material = getattr(production_release, "validate_production_signing_material", None)
        self.assertTrue(callable(validate_signing_material), "production release must validate signing material")
        with self.assertRaisesRegex(ReleaseError, "NEPK_PRODUCTION_ISSUER_KEY is missing"):
            validate_signing_material(None, PUBLISHER, bytes.fromhex(SPKI_SHA256), SPKI_SHA256, Path("/tmp/unused-key.pem"))

    def test_concurrent_ledger_ref_compare_and_swap_allocates_unique_monotonic_sequences(self):
        initialize = self.required_api("initialize_sequence_ledger")
        reserve = self.required_api("reserve_release_sequence")
        client = MemoryLedgerRef(initialize(PUBLISHER, APP, SPKI_SHA256))
        client.head_sha = "genesis-head"
        concurrent = []

        def reserve_competing_writer():
            concurrent.append(reserve(
                client,
                genesis_sha256=client.ledger["genesis_sha256"],
                publisher_id=PUBLISHER,
                app_id=APP,
                publisher_spki_sha256=SPKI_SHA256,
                batch_version="1.0.1",
                source_sha=SOURCE,
                build_input_sha256="d" * 64,
                run_id="202",
                run_attempt=1,
                run_url="https://github.com/example/repo/actions/runs/202",
            ))

        client.before_next_cas = reserve_competing_writer
        first = reserve(
            client,
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            batch_version="1.0.0",
            source_sha=SOURCE,
            build_input_sha256="c" * 64,
            run_id="201",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/201",
        )
        self.assertEqual(concurrent[0]["release_seq"], 1)
        self.assertEqual(first["release_seq"], 2)
        self.assertEqual(
            [event["release_seq"] for event in client.ledger["events"] if event["kind"] == "reserved"],
            [1, 2],
        )
        self.assertEqual(client.head_sha, "head-2")

    def test_github_ledger_ref_update_uses_non_force_fast_forward_cas(self):
        client = release.GitHubReleaseClient("example/repo", "offline-test-token")
        calls = []

        def request(method, url, payload=None, accept="application/vnd.github+json"):
            calls.append((method, url, payload))
            if method == "GET" and url.endswith("/git/ref/heads/nepk-production-sequence-ledger"):
                return {"object": {"sha": "0" * 40, "type": "commit"}}
            if method == "GET" and url.endswith(f"/git/commits/{'0' * 40}"):
                return {"tree": {"sha": "a" * 40}}
            if method == "POST" and url.endswith("/git/blobs"):
                return {"sha": "b" * 40}
            if method == "POST" and url.endswith("/git/trees"):
                return {"sha": "c" * 40}
            if method == "POST" and url.endswith("/git/commits"):
                return {"sha": "d" * 40}
            if method == "PATCH" and url.endswith("/git/refs/heads/nepk-production-sequence-ledger"):
                return {"ref": "refs/heads/nepk-production-sequence-ledger", "object": {"sha": payload["sha"]}}
            raise AssertionError((method, url, payload))

        client._request = request
        compare_and_swap = getattr(client, "compare_and_swap_sequence_ledger", None)
        self.assertTrue(callable(compare_and_swap), "GitHub release client must implement ledger ref CAS")
        self.assertTrue(compare_and_swap("0" * 40, {"version": 1, "events": [], "records": []}))
        update = next(call for call in calls if call[0] == "PATCH")
        self.assertEqual(update[2], {"sha": "d" * 40, "force": False})
        commit = next(call for call in calls if call[0] == "POST" and call[1].endswith("/git/commits"))
        self.assertEqual(commit[2]["parents"], ["0" * 40])

    def test_github_ledger_initialization_creates_only_the_new_ref(self):
        client = release.GitHubReleaseClient("example/repo", "offline-test-token")
        calls = []

        def request(method, url, payload=None, accept="application/vnd.github+json"):
            calls.append((method, url, payload))
            if method == "GET" and url.endswith("/git/ref/heads/nepk-production-sequence-ledger"):
                return None
            if method == "POST" and url.endswith("/git/blobs"):
                return {"sha": "a" * 40}
            if method == "POST" and url.endswith("/git/trees"):
                return {"sha": "b" * 40}
            if method == "POST" and url.endswith("/git/commits"):
                return {"sha": "c" * 40}
            if method == "POST" and url.endswith("/git/refs"):
                return {"ref": payload["ref"], "object": {"sha": payload["sha"]}}
            raise AssertionError((method, url, payload))

        client._request = request
        ledger = release.initialize_sequence_ledger(PUBLISHER, APP, SPKI_SHA256)
        create_initial = getattr(client, "create_initial_sequence_ledger", None)
        self.assertTrue(callable(create_initial), "GitHub release client must implement one-time ledger ref creation")
        head_sha = create_initial(ledger)
        ref_creation = next(call for call in calls if call[0] == "POST" and call[1].endswith("/git/refs"))
        self.assertEqual(head_sha, "c" * 40)
        self.assertEqual(ref_creation[2], {"ref": "refs/heads/nepk-production-sequence-ledger", "sha": "c" * 40})

    def test_reserved_version_cannot_be_rebound_to_different_source_or_build_bytes(self):
        initialize = self.required_api("initialize_sequence_ledger")
        reserve = self.required_api("reserve_release_sequence")
        client = MemoryLedgerRef(initialize(PUBLISHER, APP, SPKI_SHA256))
        client.head_sha = "genesis-head"
        kwargs = {
            "genesis_sha256": client.ledger["genesis_sha256"],
            "publisher_id": PUBLISHER,
            "app_id": APP,
            "publisher_spki_sha256": SPKI_SHA256,
            "batch_version": "1.0.0",
            "source_sha": SOURCE,
            "build_input_sha256": "c" * 64,
            "run_id": "203",
            "run_attempt": 1,
            "run_url": "https://github.com/example/repo/actions/runs/203",
        }
        first = reserve(client, **kwargs)
        self.assertEqual(first["release_seq"], 1)
        with self.assertRaisesRegex(ReleaseError, "version is already bound to different source or build bytes"):
            reserve(client, **{**kwargs, "build_input_sha256": "e" * 64, "run_id": "204"})

    def test_ledger_rejects_a_hash_valid_reservation_sequence_rollback(self):
        initialize = self.required_api("initialize_sequence_ledger")
        reserve = self.required_api("reserve_release_sequence")
        validate = self.required_api("validate_sequence_ledger")
        ledger = initialize(PUBLISHER, APP, SPKI_SHA256)
        client = MemoryLedgerRef(ledger)
        for index, version in enumerate(("1.0.0", "1.0.1"), start=210):
            reserve(
                client,
                genesis_sha256=ledger["genesis_sha256"],
                publisher_id=PUBLISHER,
                app_id=APP,
                publisher_spki_sha256=SPKI_SHA256,
                batch_version=version,
                source_sha=SOURCE,
                build_input_sha256=chr(index - 110) * 64,
                run_id=str(index),
                run_attempt=1,
                run_url=f"https://github.com/example/repo/actions/runs/{index}",
            )
        ledger = copy.deepcopy(client.ledger)
        previous = ledger["genesis_sha256"]
        for event, sequence in zip(ledger["events"][1:], (2, 1)):
            event["release_seq"] = sequence
            event["previous_digest"] = previous
            event["digest"] = release.canonical_json_sha256({key: value for key, value in event.items() if key != "digest"})
            previous = event["digest"]
        with self.assertRaisesRegex(ReleaseError, "reservation order moved backward"):
            validate(ledger, ledger["genesis_sha256"], PUBLISHER, APP, SPKI_SHA256)

    def test_authorized_ledger_record_hash_chains_signed_pair_and_rejects_conflicting_pair(self):
        initialize = self.required_api("initialize_sequence_ledger")
        reserve = self.required_api("reserve_release_sequence")
        complete = self.required_api("complete_release_sequence")
        mark_signed = self.required_api("mark_sequence_signed")
        mark_published = self.required_api("mark_sequence_published")
        client = MemoryLedgerRef(initialize(PUBLISHER, APP, SPKI_SHA256))
        client.head_sha = "genesis-head"
        reservation = reserve(
            client,
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            batch_version="1.0.0",
            source_sha=SOURCE,
            build_input_sha256="c" * 64,
            run_id="205",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/205",
        )
        report = {
            "publisher_id": PUBLISHER,
            "app_id": APP,
            "release_seq": 1,
            "publisher_key_sha256": SPKI_SHA256,
            "native_version": [4, 0, 0],
            "ui_version": [1, 0, 0],
            "native_tbs_sha256": "1" * 64,
            "ui_tbs_sha256": "2" * 64,
            "pair_tbs_sha256": "3" * 64,
            "package_sha256": "4" * 64,
        }
        record = complete(
            client,
            reservation,
            report,
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            run_id="205",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/205",
        )
        self.assertEqual(record["status"], "authorized")
        self.assertEqual(record["package_sha256"], "4" * 64)
        self.assertEqual(client.ledger["events"][-1]["previous_digest"], reservation["digest"])
        event_count = len(client.ledger["events"])
        complete(
            client,
            reservation,
            report,
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            run_id="205",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/205",
        )
        self.assertEqual(len(client.ledger["events"]), event_count)
        authorization_ledger_sha256 = release.canonical_json_sha256(client.ledger)
        record = mark_signed(
            client,
            record["record_id"],
            release_url="https://github.com/example/repo/releases/tag/v1.0.0",
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            run_id="205",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/205",
        )
        self.assertEqual(record["status"], "signed")
        self.assertEqual(client.ledger["events"][-1]["kind"], "signed")
        signed_event_count = len(client.ledger["events"])
        mark_signed(
            client,
            record["record_id"],
            release_url="https://github.com/example/repo/releases/tag/v1.0.0",
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            run_id="205",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/205",
        )
        self.assertEqual(len(client.ledger["events"]), signed_event_count)
        published = mark_published(
            client,
            record["record_id"],
            release_url="https://github.com/example/repo/releases/tag/v1.0.0",
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            run_id="205",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/205",
        )
        self.assertEqual(published["status"], "published")
        published_event_count = len(client.ledger["events"])
        mark_published(
            client,
            record["record_id"],
            release_url="https://github.com/example/repo/releases/tag/v1.0.0",
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            run_id="205",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/205",
        )
        self.assertEqual(len(client.ledger["events"]), published_event_count)
        snapshot_for_record = self.required_api("authorization_snapshot_for_record")
        authorization_snapshot = snapshot_for_record(
            client.ledger,
            record["record_id"],
            client.ledger["genesis_sha256"],
            PUBLISHER,
            APP,
            SPKI_SHA256,
        )
        self.assertEqual(release.canonical_json_sha256(authorization_snapshot), authorization_ledger_sha256)
        self.assertEqual(authorization_snapshot["records"][-1]["status"], "authorized")
        with self.assertRaisesRegex(ReleaseError, "same release sequence is bound to different signed package bytes"):
            complete(
                client,
                reservation,
                {**report, "package_sha256": "5" * 64, "pair_tbs_sha256": "6" * 64},
                genesis_sha256=client.ledger["genesis_sha256"],
                publisher_id=PUBLISHER,
                app_id=APP,
                publisher_spki_sha256=SPKI_SHA256,
                run_id="205",
                run_attempt=1,
                run_url="https://github.com/example/repo/actions/runs/205",
            )

    def test_generated_release_request_uses_source_versions_and_pinned_authorization_snapshot(self):
        import nepk_v1_1_production_release as production_release

        initialize = self.required_api("initialize_sequence_ledger")
        reserve = self.required_api("reserve_release_sequence")
        complete = self.required_api("complete_release_sequence")
        client = MemoryLedgerRef(initialize(PUBLISHER, APP, SPKI_SHA256))
        client.head_sha = "genesis-head"
        reservation = reserve(
            client,
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            batch_version="1.0.0",
            source_sha=SOURCE,
            build_input_sha256="c" * 64,
            run_id="208",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/208",
        )
        record = complete(
            client,
            reservation,
            {
                "publisher_id": PUBLISHER,
                "app_id": APP,
                "release_seq": 1,
                "publisher_key_sha256": SPKI_SHA256,
                "native_version": [4, 2, 0],
                "ui_version": [1, 3, 0],
                "native_tbs_sha256": "1" * 64,
                "ui_tbs_sha256": "2" * 64,
                "pair_tbs_sha256": "3" * 64,
                "package_sha256": "4" * 64,
            },
            genesis_sha256=client.ledger["genesis_sha256"],
            publisher_id=PUBLISHER,
            app_id=APP,
            publisher_spki_sha256=SPKI_SHA256,
            run_id="208",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/208",
        )
        request, snapshot = production_release._request_and_snapshot(
            client.ledger,
            record,
            client.ledger["genesis_sha256"],
            PUBLISHER,
            SPKI_SHA256,
        )
        validated = release.validate_release_request(
            request,
            expected_source_sha=SOURCE,
            expected_action="publish",
            expected_ledger_sha256=release.canonical_json_sha256(snapshot),
        )
        self.assertEqual(validated["apps"][0]["native_version"], [4, 2, 0])
        self.assertEqual(validated["apps"][0]["ui_version"], [1, 3, 0])
        self.assertEqual(validated["apps"][0]["asset_name"], "line-crossing-1.0.0.neapp")

    def test_wrong_signer_key_and_test_only_spki_are_rejected(self):
        import nepk_v1_1_production_release as production_release

        validate_signing_material = getattr(production_release, "validate_production_signing_material", None)
        self.assertTrue(callable(validate_signing_material), "production release must validate signing material")
        expected_key = ec.generate_private_key(ec.SECP256R1())
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        expected_spki = expected_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        expected_fingerprint = hashlib.sha256(expected_spki).hexdigest()
        wrong_secret = wrong_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "issuer.pem"
            with self.assertRaisesRegex(ReleaseError, "does not match the configured production SPKI"):
                validate_signing_material(wrong_secret, PUBLISHER, expected_spki, expected_fingerprint, key_path)
            with self.assertRaisesRegex(ReleaseError, "TEST ONLY"):
                validate_signing_material(
                    wrong_secret,
                    PUBLISHER,
                    b"not-a-production-spki",
                    "06e732b1b94daeeef433297f7a8e797bf72b2fd3b882a4ec6a5490352931ebda",
                    key_path,
                )

    def test_published_same_version_same_bytes_is_read_only_idempotent(self):
        publish = self.required_api("publish_one_click_release")
        app = self.make_app()
        plan = self.make_plan(app)
        client = MemoryOneClickApi()
        first = publish(plan, client, authorized=False, simulation=True)
        events_after_publish = list(client.events)
        second = publish(plan, client, authorized=False, simulation=True)
        self.assertEqual(first["result"], "PUBLISHED")
        self.assertEqual(second["result"], "IDEMPOTENT")
        self.assertEqual(client.events, events_after_publish)

    def test_same_version_with_different_package_bytes_is_rejected(self):
        publish = self.required_api("publish_one_click_release")
        original = self.make_app(sequence=7, payload=b"original native")
        original_plan = self.make_plan(original)
        client = MemoryOneClickApi()
        publish(original_plan, client, authorized=False, simulation=True)
        changed = self.make_app(sequence=8, payload=b"changed native", native_version=(4, 0, 2), ui_version=(1, 0, 2))
        previous = copy.deepcopy(original["record"])
        previous["status"] = "signed"
        changed_record = copy.deepcopy(changed["record"])
        changed_record["previous_high_water"] = 7
        changed_plan = self.make_plan(changed, ledger_records=[previous, changed_record])
        events_before_conflict = list(client.events)
        with self.assertRaisesRegex(ReleaseError, "conflict"):
            publish(changed_plan, client, authorized=False, simulation=True)
        self.assertEqual(client.events, events_before_conflict)

    def test_existing_version_tag_at_another_source_is_never_moved(self):
        publish = self.required_api("publish_one_click_release")
        plan = self.make_plan(self.make_app())
        client = MemoryOneClickApi()
        client.tags[plan["tag"]] = {"object": {"sha": "b" * 40, "type": "commit"}}
        before = copy.deepcopy(client.tags)
        with self.assertRaisesRegex(ReleaseError, "different source SHA"):
            publish(plan, client, authorized=False, simulation=True)
        self.assertEqual(client.tags, before)
        self.assertEqual(client.events, [])

    def test_incomplete_or_byte_mismatched_draft_never_publishes(self):
        publish = self.required_api("publish_one_click_release")
        app = self.make_app()
        plan = self.make_plan(app)
        incomplete = MemoryOneClickApi()
        incomplete.fail_upload_number = 1
        with self.assertRaisesRegex(ReleaseError, "injected partial upload"):
            publish(plan, incomplete, authorized=False, simulation=True)
        self.assertTrue(incomplete.releases[plan["tag"]]["draft"])
        self.assertNotIn(("publish", plan["tag"]), incomplete.events)
        mismatched = MemoryOneClickApi()
        publish(plan, mismatched, authorized=False, simulation=True)
        asset_id = mismatched.releases[plan["tag"]]["assets"][0]["id"]
        mismatched.asset_bytes[asset_id] = b"different signed package bytes"
        events_before_check = list(mismatched.events)
        with self.assertRaisesRegex(ReleaseError, "conflict"):
            publish(plan, mismatched, authorized=False, simulation=True)
        self.assertEqual(mismatched.events, events_before_check)
        prerelease = MemoryOneClickApi()
        publish(plan, prerelease, authorized=False, simulation=True)
        prerelease.releases[plan["tag"]]["prerelease"] = True
        with self.assertRaisesRegex(ReleaseError, "must not be marked as a prerelease"):
            publish(plan, prerelease, authorized=False, simulation=True)

    def test_failed_publish_recovers_from_complete_draft_without_duplicate_asset(self):
        publish = self.required_api("publish_one_click_release")
        self.assertIn("before_publish", inspect.signature(publish).parameters)
        initialize = self.required_api("initialize_sequence_ledger")
        reserve = self.required_api("reserve_release_sequence")
        complete = self.required_api("complete_release_sequence")
        mark_signed = self.required_api("mark_sequence_signed")
        app = self.make_app(sequence=1)
        plan = self.make_plan(app)
        publisher_id = self.fixture.publisher_id
        spki_sha256 = hashlib.sha256(self.fixture.spki).hexdigest()
        ledger = initialize(publisher_id, APP, spki_sha256)
        ledger_client = MemoryLedgerRef(ledger)
        ledger_client.head_sha = "genesis-head"
        reservation = reserve(
            ledger_client,
            genesis_sha256=ledger["genesis_sha256"],
            publisher_id=publisher_id,
            app_id=APP,
            publisher_spki_sha256=spki_sha256,
            batch_version="1.0.0",
            source_sha=SOURCE,
            build_input_sha256="c" * 64,
            run_id="206",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/206",
        )
        record = complete(
            ledger_client,
            reservation,
            app["report"],
            genesis_sha256=ledger["genesis_sha256"],
            publisher_id=publisher_id,
            app_id=APP,
            publisher_spki_sha256=spki_sha256,
            run_id="206",
            run_attempt=1,
            run_url="https://github.com/example/repo/actions/runs/206",
        )
        client = MemoryOneClickApi()
        client.fail_publish_once = True
        release_url = f"https://github.com/example/repo/releases/tag/{plan['tag']}"

        def persist_signed(release_data):
            client.events.append(("ledger-signed", release_data["tag_name"]))
            mark_signed(
                ledger_client,
                record["record_id"],
                release_url=release_url,
                genesis_sha256=ledger["genesis_sha256"],
                publisher_id=publisher_id,
                app_id=APP,
                publisher_spki_sha256=spki_sha256,
                run_id="206",
                run_attempt=1,
                run_url="https://github.com/example/repo/actions/runs/206",
            )

        with self.assertRaisesRegex(ReleaseError, "injected publish failure"):
            publish(plan, client, authorized=False, simulation=True, before_publish=persist_signed)
        self.assertTrue(client.releases[plan["tag"]]["draft"])
        self.assertEqual(len(client.releases[plan["tag"]]["assets"]), 1)
        self.assertEqual(ledger_client.ledger["records"][0]["status"], "signed")
        first_upload_count = len([event for event in client.events if event[0] == "upload"])
        recovered = publish(
            plan,
            client,
            authorized=False,
            simulation=True,
            before_publish=persist_signed,
            after_publish=lambda release_data: self.required_api("mark_sequence_published")(
                ledger_client,
                record["record_id"],
                release_url=release_url,
                genesis_sha256=ledger["genesis_sha256"],
                publisher_id=publisher_id,
                app_id=APP,
                publisher_spki_sha256=spki_sha256,
                run_id="206",
                run_attempt=1,
                run_url="https://github.com/example/repo/actions/runs/206",
            ),
        )
        self.assertEqual(recovered["result"], "PUBLISHED")
        self.assertEqual(len([event for event in client.events if event[0] == "upload"]), first_upload_count)
        self.assertEqual(len([event for event in client.events if event[0] == "publish"]), 1)
        self.assertLess(client.events.index(("ledger-signed", plan["tag"])), client.events.index(("publish", plan["tag"])))
        published = ledger_client.ledger["records"][0]
        self.assertEqual(published["status"], "published")
        self.assertEqual([row["release_seq"] for row in ledger_client.ledger["records"]], [1])
        self.assertEqual([event["kind"] for event in ledger_client.ledger["events"]], ["genesis", "reserved", "authorized", "signed", "published"])


if __name__ == "__main__":
    unittest.main()
