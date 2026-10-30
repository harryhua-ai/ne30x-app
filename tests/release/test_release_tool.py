import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "package" / "release"))

import release_tool

PROVENANCE = {
    "artifact_type": "unsigned NEAPP v5 package",
    "format": "neapp-v5-unsigned",
    "app_id": "line-crossing",
    "native_version": [4, 2, 8],
    "ui_version": [1, 2, 10],
    "source_commit": "a" * 40,
    "signing_dependencies": "none: no private key, no SPKI, no signature",
    "package": {"sha256": "b" * 64, "len": 123456},
    "host_policy": {
        "host_caps": "0x3ff",
        "event_max": 1576,
        "state_quota": 512,
        "control_max": 512,
        "snapshot_max": 1024,
        "report_max": 6144,
    },
    "verification_boundary": "abi-0x40000",
}

VERIFICATION = {"result": "PASS"}


class VersionValidationTest(unittest.TestCase):
    def test_accepts_strict_semver_with_v_prefix(self):
        self.assertEqual(release_tool.parse_version("v1.2.3"), (1, 2, 3))
        self.assertEqual(release_tool.parse_version("v10.0.0"), (10, 0, 0))

    def test_rejects_wrong_shapes(self):
        for bad in ("1.2.3", "v1.2", "v1.2.3.4", "v1.2.3-rc1", "V1.2.3",
                    "v01.2.3", "release-1", "", "vX.Y.Z"):
            with self.assertRaises(release_tool.ReleaseToolError, msg=bad):
                release_tool.parse_version(bad)


class CommitClassificationTest(unittest.TestCase):
    def test_classifies_conventional_subjects(self):
        self.assertEqual(release_tool.classify_subject("feat: add x"), "Added")
        self.assertEqual(
            release_tool.classify_subject("feat(ui): add y"), "Added")
        self.assertEqual(release_tool.classify_subject("fix: repair z"), "Fixed")
        self.assertEqual(
            release_tool.classify_subject("fix(line-crossing): w"), "Fixed")
        self.assertEqual(
            release_tool.classify_subject("docs: update readme"), "Changed")
        self.assertEqual(
            release_tool.classify_subject("merge pull request #1"), "Changed")

    def test_summarize_keeps_newest_and_counts_overflow(self):
        subjects = [f"feat: add {i}" for i in range(5)]
        buckets = release_tool.summarize_commits(subjects, max_commits=3)
        self.assertEqual(buckets["Added"], ["feat: add 0", "feat: add 1",
                                            "feat: add 2"])
        self.assertEqual(
            buckets["Changed"],
            ["... and 2 earlier commits (see repository history)"])

    def test_summarize_empty(self):
        self.assertEqual(release_tool.summarize_commits([]), {})


class RenderNotesTest(unittest.TestCase):
    def render(self, provenance=PROVENANCE, verification=VERIFICATION,
               commits=None, limitations=None):
        return release_tool.render_notes("v1.0.0", provenance, verification,
                                         commits or {}, limitations or [])

    def test_notes_carry_package_identity_and_versions_separately(self):
        text = self.render()
        self.assertIn("| Native version | 4.2.8 |", text)
        self.assertIn("| UI version | 1.2.10 |", text)
        self.assertIn("| Repository version | v1.0.0 (release batch identity) |", text)
        self.assertIn("b" * 64, text)
        self.assertIn("a" * 40, text)
        self.assertIn("recorded", text)
        self.assertIn("**PASS**", text)

    def test_notes_reject_failed_verification(self):
        with self.assertRaises(release_tool.ReleaseToolError):
            self.render(verification={"result": "FORMAT_MAGIC_MISMATCH"})

    def test_notes_reject_incomplete_provenance(self):
        broken = dict(PROVENANCE)
        broken["source_commit"] = ""
        with self.assertRaises(release_tool.ReleaseToolError):
            self.render(provenance=broken)

    def test_notes_render_commits_and_limitations(self):
        commits = {"Added": ["feat: add x"], "Fixed": ["fix: y"]}
        text = self.render(commits=commits, limitations=["item one"])
        self.assertIn("#### Added", text)
        self.assertIn("- feat: add x", text)
        self.assertIn("#### Fixed", text)
        self.assertIn("- item one", text)

    def test_notes_without_history_states_it(self):
        self.assertIn("No recorded commit history for this range.", self.render())

    def test_limitations_fallback(self):
        self.assertIn("- None recorded.", self.render())


class KnownLimitationsTest(unittest.TestCase):
    def test_parses_bullets_and_skips_headings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "limits.md"
            path.write_text("# Known limitations\n\n- first\n- second\n",
                            encoding="utf-8")
            self.assertEqual(release_tool.load_known_limitations(path),
                             ["first", "second"])

    def test_missing_file_means_empty(self):
        self.assertEqual(
            release_tool.load_known_limitations(Path("/nonexistent/x.md")), [])


class CheckConflictsTest(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.responses = []

    def fake_gh(self, args):
        self.calls.append(args[0] if args[0] != "api" else args[1])
        return self.responses.pop(0)

    def run_check(self):
        original = release_tool.gh
        release_tool.gh = self.fake_gh
        try:
            return release_tool.check_conflicts("v1.0.0", "harryhua-ai/ne30x-app")
        finally:
            release_tool.gh = original

    def test_no_conflicts_when_everything_missing(self):
        self.responses = [(1, "gh: Not Found (HTTP 404)"),
                          (1, "gh: Not Found (HTTP 404)"), (0, "[]")]
        self.assertEqual(self.run_check(), [])

    def test_existing_tag_conflicts(self):
        self.responses = [(0, '{"ref": "refs/tags/v1.0.0"}'),
                          (1, "gh: Not Found (HTTP 404)"), (0, "[]")]
        conflicts = self.run_check()
        self.assertEqual(conflicts, ["tag v1.0.0 already exists"])

    def test_existing_published_release_conflicts(self):
        self.responses = [(1, "gh: Not Found (HTTP 404)"),
                          (0, '{"id": 1}'), (0, "[]")]
        conflicts = self.run_check()
        self.assertEqual(conflicts, ["release v1.0.0 already exists"])

    def test_existing_draft_conflicts(self):
        drafts = json.dumps([[{"draft": True, "tag_name": "v1.0.0"},
                              {"draft": True, "tag_name": "v2.0.0"}]])
        self.responses = [(1, "gh: Not Found (HTTP 404)"),
                          (1, "gh: Not Found (HTTP 404)"), (0, drafts)]
        conflicts = self.run_check()
        self.assertEqual(conflicts, ["draft release v1.0.0 already exists"])

    def test_draft_conflict_detected_on_second_page(self):
        page_one = json.dumps([{"draft": True, "tag_name": "v9.0.0"}] * 100)
        page_two = json.dumps([{"draft": True, "tag_name": "v1.0.0"}])
        self.responses = [(1, "gh: Not Found (HTTP 404)"),
                          (1, "gh: Not Found (HTTP 404)"),
                          (0, json.dumps([json.loads(page_one),
                                          json.loads(page_two)]))]
        conflicts = self.run_check()
        self.assertEqual(conflicts, ["draft release v1.0.0 already exists"])

    def test_cross_page_without_conflict_returns_empty(self):
        page_one = json.dumps([{"draft": True, "tag_name": "v9.0.0"}])
        page_two = json.dumps([{"draft": False, "tag_name": "v1.0.0"}])
        self.responses = [(1, "gh: Not Found (HTTP 404)"),
                          (1, "gh: Not Found (HTTP 404)"),
                          (0, json.dumps([json.loads(page_one),
                                          json.loads(page_two)]))]
        self.assertEqual(self.run_check(), [])

    def test_tag_endpoint_denial_fails_closed(self):
        self.responses = [(1, "gh: Forbidden (HTTP 403)")]
        with self.assertRaises(release_tool.ReleaseToolError):
            self.run_check()

    def test_release_endpoint_denial_fails_closed(self):
        self.responses = [(1, "gh: Not Found (HTTP 404)"),
                          (1, "gh: auth error (HTTP 401)")]
        with self.assertRaises(release_tool.ReleaseToolError):
            self.run_check()

    def test_gh_api_hard_failure_fails_closed(self):
        self.responses = [(1, "gh: Not Found (HTTP 404)"),
                          (1, "gh: Not Found (HTTP 404)"),
                          (1, "gh: auth error")]
        with self.assertRaises(release_tool.ReleaseToolError):
            self.run_check()

    def test_403_body_mentioning_404_fails_closed(self):
        self.responses = [(1, "gh: Forbidden (HTTP 403): hint 404")]
        with self.assertRaises(release_tool.ReleaseToolError):
            self.run_check()

    def test_404_status_detected_without_not_found_text(self):
        self.responses = [(1, "gh: request failed (HTTP 404)"),
                          (1, "gh: request failed (HTTP 404)"), (0, "[]")]
        self.assertEqual(self.run_check(), [])


class CreateDraftTest(unittest.TestCase):
    def test_missing_asset_fails_before_gh(self):
        calls = []
        original = release_tool.gh

        def fake_gh(args):
            calls.append(args)
            return 0, "url"

        release_tool.gh = fake_gh
        try:
            with self.assertRaises(release_tool.ReleaseToolError):
                release_tool.create_draft("v1.0.0", "a" * 40, "t",
                                          Path("/nonexistent/notes.md"), [])
        finally:
            release_tool.gh = original
        self.assertEqual(calls, [])

    def test_failed_create_deletes_nothing(self):
        calls = []

        def fake_gh(args):
            calls.append((args[0], args[1] if len(args) > 1 else None))
            return 1, "boom"

        original = release_tool.gh
        release_tool.gh = fake_gh
        try:
            with tempfile.TemporaryDirectory() as tmp:
                notes = Path(tmp) / "notes.md"
                notes.write_text("body", encoding="utf-8")
                with self.assertRaises(release_tool.ReleaseToolError) as ctx:
                    release_tool.create_draft("v1.0.0", "a" * 40, "t", notes, [])
        finally:
            release_tool.gh = original
        self.assertIn("nothing deleted", str(ctx.exception))
        self.assertNotIn(("release", "delete"), calls)
        self.assertEqual([call[1] for call in calls], ["create"])

    def test_failed_upload_removes_owned_draft(self):
        calls = []

        def fake_gh(args):
            calls.append((args[0], args[1] if len(args) > 1 else None))
            if args[1] == "create":
                return 0, "https://example.com/draft\n"
            if args[1] == "delete":
                return 0, ""
            return 1, "upload boom"

        original = release_tool.gh
        release_tool.gh = fake_gh
        try:
            with tempfile.TemporaryDirectory() as tmp:
                notes = Path(tmp) / "notes.md"
                notes.write_text("body", encoding="utf-8")
                with self.assertRaises(release_tool.ReleaseToolError) as ctx:
                    release_tool.create_draft("v1.0.0", "a" * 40, "t", notes, [])
        finally:
            release_tool.gh = original
        self.assertIn("was removed", str(ctx.exception))
        self.assertEqual(calls[-1], ("release", "delete"))
        self.assertIn(("release", "create"), [c for c in calls])

    def test_failed_upload_delete_failure_requires_manual_verification(self):
        calls = []

        def fake_gh(args):
            calls.append((args[0], args[1] if len(args) > 1 else None))
            if args[1] == "create":
                return 0, "https://example.com/draft\n"
            if args[1] == "delete":
                return 1, "delete boom"
            return 1, "upload boom"

        original = release_tool.gh
        release_tool.gh = fake_gh
        try:
            with tempfile.TemporaryDirectory() as tmp:
                notes = Path(tmp) / "notes.md"
                notes.write_text("body", encoding="utf-8")
                with self.assertRaises(release_tool.ReleaseToolError) as ctx:
                    release_tool.create_draft("v1.0.0", "a" * 40, "t", notes,
                                              [])
        finally:
            release_tool.gh = original
        self.assertNotIn("was removed", str(ctx.exception))
        self.assertIn("could NOT be confirmed removed", str(ctx.exception))
        self.assertIn("verify ownership and remove it manually",
                      str(ctx.exception))
        self.assertEqual(calls[-1], ("release", "delete"))

    def test_successful_create_returns_url_without_delete(self):
        calls = []

        def fake_gh(args):
            calls.append((args[0], args[1] if len(args) > 1 else None))
            if args[1] == "create":
                return 0, "https://example.com/draft\n"
            return 0, ""

        original = release_tool.gh
        release_tool.gh = fake_gh
        try:
            with tempfile.TemporaryDirectory() as tmp:
                notes = Path(tmp) / "notes.md"
                notes.write_text("body", encoding="utf-8")
                asset = Path(tmp) / "a.bin"
                asset.write_bytes(b"x")
                url = release_tool.create_draft("v1.0.0", "a" * 40, "t",
                                                notes, [asset])
        finally:
            release_tool.gh = original
        self.assertEqual(url, "https://example.com/draft")
        self.assertNotIn(("release", "delete"), calls)


if __name__ == "__main__":
    unittest.main()
