from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "package" / "vnext"))

from nepk_v1_1_pack import NON_PRODUCTION_PUBLISHER_IDS, PackError, _ledger_history, canonical_json_sha256
from nepk_v1_1_verify import NePKError, TrustedHistory, verify_nepk

VERSION_PATTERN = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}\Z")


class ReleaseError(ValueError):
    pass


class _StripAuthRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        parsed = urllib.parse.urlsplit(new_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            return None
        redirected = super().redirect_request(request, file_pointer, code, message, headers, new_url)
        if redirected is not None:
            redirected.remove_header("Authorization")
            redirected.remove_header("X-GitHub-Api-Version")
        return redirected


def canonical_json_bytes(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _version_tuple(value: str, field: str) -> tuple[int, int, int]:
    if not isinstance(value, str) or VERSION_PATTERN.fullmatch(value) is None:
        raise ReleaseError(f"{field} must be a canonical X.Y.Z version")
    version = tuple(int(part) for part in value.split("."))
    if any(part > 0xFFFF for part in version):
        raise ReleaseError(f"{field} segments must fit u16")
    return version


def _safe_text(value, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or any(ord(char) < 32 for char in value):
        raise ReleaseError(f"{field} must be nonempty printable text")
    return value.strip()


def validate_environment_configuration(environment: dict, branch_policies: dict) -> None:
    if not isinstance(environment, dict) or environment.get("name") != "production":
        raise ReleaseError("protected production Environment is missing or has the wrong name")
    rules = environment.get("protection_rules")
    reviewer_rules = [rule for rule in rules or [] if isinstance(rule, dict) and rule.get("type") == "required_reviewers"]
    if not any(
        isinstance(rule.get("reviewers"), list)
        and len(rule["reviewers"]) > 0
        and all(
            isinstance(reviewer, dict)
            and reviewer.get("type") in {"User", "Team"}
            and isinstance(reviewer.get("reviewer"), dict)
            and isinstance(reviewer["reviewer"].get("id"), int)
            and not isinstance(reviewer["reviewer"].get("id"), bool)
            and reviewer["reviewer"]["id"] > 0
            for reviewer in rule["reviewers"]
        )
        and rule.get("prevent_self_review") is True
        for rule in reviewer_rules
    ):
        raise ReleaseError("production Environment must require a non-self reviewer")
    policy = environment.get("deployment_branch_policy")
    if not isinstance(policy, dict) or policy.get("protected_branches") is not False or policy.get("custom_branch_policies") is not True:
        raise ReleaseError("production Environment must restrict deployments to the exact main branch policy")
    rows = branch_policies.get("branch_policies") if isinstance(branch_policies, dict) else None
    if not isinstance(rows, list) or len(rows) != 1:
        raise ReleaseError("production Environment must allow only the main branch")
    row = rows[0]
    if not isinstance(row, dict) or row.get("name") != "main" or row.get("type", "branch") != "branch":
        raise ReleaseError("production Environment branch policy must be exactly main")


def validate_release_request(
    request: dict,
    *,
    expected_source_sha: str | None = None,
    expected_action: str | None = None,
    expected_ledger_sha256: str | None = None,
) -> dict:
    if not isinstance(request, dict) or request.get("version") != 1:
        raise ReleaseError("release request must use version 1")
    action = request.get("action")
    if action not in {"draft", "publish", "simulate"}:
        raise ReleaseError("release action must be draft, publish, or simulate")
    if expected_action is not None and action != expected_action:
        raise ReleaseError("release request action does not match the manually selected action")
    batch_version = request.get("batch_version")
    _version_tuple(batch_version, "batch_version")
    source_sha = request.get("source_sha")
    if not isinstance(source_sha, str) or COMMIT_PATTERN.fullmatch(source_sha) is None:
        raise ReleaseError("source_sha must be a full lowercase Git commit SHA")
    if expected_source_sha is not None and source_sha != expected_source_sha:
        raise ReleaseError("release request source SHA does not equal the accepted main SHA")
    authorization = request.get("authorization")
    if not isinstance(authorization, dict):
        raise ReleaseError("release authorization input is missing")
    request_id = _safe_text(authorization.get("request_id"), "authorization request_id")
    authorization_ref = _safe_text(authorization.get("authorization_ref"), "authorization_ref")
    parsed_ref = urllib.parse.urlsplit(authorization_ref)
    if parsed_ref.scheme != "https" or not parsed_ref.netloc or parsed_ref.username or parsed_ref.password or parsed_ref.query or parsed_ref.fragment or any(char.isspace() for char in authorization_ref):
        raise ReleaseError("authorization_ref must be an HTTPS reference without credentials, query, or fragment")
    if authorization.get("source_sha") != source_sha or authorization.get("action") != action:
        raise ReleaseError("authorization record is for a different action or source SHA")
    ledger = request.get("sequence_ledger")
    if not isinstance(ledger, dict) or ledger.get("version") != 1 or not isinstance(ledger.get("records"), list):
        raise ReleaseError("release request must include the pinned sequence ledger")
    ledger_sha256 = canonical_json_sha256(ledger)
    if expected_ledger_sha256 is None or SHA256_PATTERN.fullmatch(expected_ledger_sha256) is None:
        raise ReleaseError("protected production sequence-ledger digest is not configured")
    if ledger_sha256 != expected_ledger_sha256:
        raise ReleaseError("sequence ledger does not match the protected Environment digest")
    apps = request.get("apps")
    if not isinstance(apps, list) or not apps:
        raise ReleaseError("release must select at least one app")
    seen_app_ids = set()
    seen_assets = set()
    validated_apps = []
    for app in apps:
        if not isinstance(app, dict):
            raise ReleaseError("selected app entry is malformed")
        app_id = app.get("app_id")
        publisher_id = app.get("publisher_id")
        if not isinstance(app_id, str) or IDENTIFIER_PATTERN.fullmatch(app_id) is None:
            raise ReleaseError("selected app_id is not canonical")
        if not isinstance(publisher_id, str) or IDENTIFIER_PATTERN.fullmatch(publisher_id) is None:
            raise ReleaseError("selected publisher_id is not canonical")
        if app_id in seen_app_ids:
            raise ReleaseError("release request contains duplicate app_id values")
        seen_app_ids.add(app_id)
        native_version = _version_tuple(app.get("native_version"), f"{app_id} native_version")
        ui_version = _version_tuple(app.get("ui_version"), f"{app_id} ui_version")
        release_seq = app.get("release_seq")
        if isinstance(release_seq, bool) or not isinstance(release_seq, int) or not 1 <= release_seq <= 0xFFFFFFFFFFFFFFFF:
            raise ReleaseError(f"{app_id} release_seq must be a nonzero u64")
        record_id = _safe_text(app.get("sequence_record_id"), f"{app_id} sequence_record_id")
        compatibility = _safe_text(app.get("compatibility"), f"{app_id} compatibility")
        record, _, _ = _ledger_history(
            ledger, expected_ledger_sha256, record_id,
            publisher_id, app_id, release_seq, source_sha,
        )
        if record.get("native_version") != list(native_version) or record.get("ui_version") != list(ui_version):
            raise ReleaseError(f"{app_id} versions do not match its authorized sequence record")
        for name in ("native_tbs_sha256", "ui_tbs_sha256", "pair_tbs_sha256", "package_sha256", "publisher_spki_sha256"):
            if not isinstance(record.get(name), str) or SHA256_PATTERN.fullmatch(record[name]) is None:
                raise ReleaseError(f"{app_id} sequence record lacks a valid {name}")
        asset_name = f"{app_id}-{batch_version}.neapp"
        if asset_name.casefold() in seen_assets:
            raise ReleaseError("release asset names collide under case folding")
        seen_assets.add(asset_name.casefold())
        validated_apps.append({
            "app_id": app_id,
            "publisher_id": publisher_id,
            "native_version": list(native_version),
            "ui_version": list(ui_version),
            "release_seq": release_seq,
            "sequence_record_id": record_id,
            "compatibility": compatibility,
            "asset_name": asset_name,
        })
    return {
        "action": action,
        "batch_version": batch_version,
        "tag": f"v{batch_version}",
        "source_sha": source_sha,
        "request_id": request_id,
        "authorization_ref": authorization_ref,
        "ledger_sha256": ledger_sha256,
        "apps": validated_apps,
    }


def _trusted_history(previous: dict | None) -> TrustedHistory | None:
    if previous is None:
        return None
    return TrustedHistory(
        publisher_id=previous["publisher_id"],
        app_id=previous["app_id"],
        publisher_key_sha256=previous["publisher_key_sha256"],
        release_seq=previous["release_seq"],
        native_tbs_sha256=previous["native_tbs_sha256"],
        ui_tbs_sha256=previous["ui_tbs_sha256"],
        pair_tbs_sha256=previous["pair_tbs_sha256"],
        native_version=tuple(previous["native_version"]),
        ui_version=tuple(previous["ui_version"]),
    )


def _markdown_value(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("`", "'").replace("\n", " ").replace("\r", " ")


def build_release_plan(
    request: dict,
    package_paths: dict[str, Path],
    provenance_paths: dict[str, Path],
    trusted_spki_by_publisher: dict[str, bytes],
    independent_reports: dict[str, dict],
    *,
    expected_source_sha: str,
    expected_ledger_sha256: str,
) -> dict:
    validated = validate_release_request(
        request,
        expected_source_sha=expected_source_sha,
        expected_action=request.get("action") if isinstance(request, dict) else None,
        expected_ledger_sha256=expected_ledger_sha256,
    )
    if validated["action"] != "simulate" and any(app["publisher_id"] in NON_PRODUCTION_PUBLISHER_IDS for app in validated["apps"]):
        raise ReleaseError("known TEST ONLY publishers cannot create production release plans")
    ledger = request["sequence_ledger"]
    plan_apps = []
    for app in validated["apps"]:
        app_id = app["app_id"]
        package_path = Path(package_paths[app_id])
        provenance_path = Path(provenance_paths[app_id])
        for path, label in ((package_path, "package"), (provenance_path, "provenance")):
            try:
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ReleaseError(f"{app_id} {label} must be a regular non-symlink file")
            except OSError as error:
                raise ReleaseError(f"{app_id} {label} is unavailable") from error
        package = package_path.read_bytes()
        actual_sha256 = hashlib.sha256(package).hexdigest()
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        trust = trusted_spki_by_publisher.get(app["publisher_id"])
        if not isinstance(trust, bytes) or not trust:
            raise ReleaseError(f"{app_id} production publisher SPKI is not configured")
        try:
            report = verify_nepk(
                package,
                {app["publisher_id"]: trust},
                expected_publisher_id=app["publisher_id"],
                expected_app_id=app_id,
                trusted_history=_trusted_history(_ledger_history(
                    ledger, expected_ledger_sha256, app["sequence_record_id"],
                    app["publisher_id"], app_id, app["release_seq"], validated["source_sha"],
                )[1]),
            )
        except NePKError as error:
            raise ReleaseError(f"{app_id} independent package verification failed: {error.code}") from error
        record, _, _ = _ledger_history(
            ledger, expected_ledger_sha256, app["sequence_record_id"],
            app["publisher_id"], app_id, app["release_seq"], validated["source_sha"],
        )
        if report["release_seq"] != app["release_seq"]:
            raise ReleaseError(f"{app_id} signed package seq differs from the authorized seq")
        if report["native_version"] != app["native_version"] or report["ui_version"] != app["ui_version"]:
            raise ReleaseError(f"{app_id} signed internal versions differ from the release request")
        if report["publisher_key_sha256"] != hashlib.sha256(trust).hexdigest():
            raise ReleaseError(f"{app_id} signer SPKI differs from the configured issuer")
        expected_report_fields = {
            "package_sha256": actual_sha256,
            "native_tbs_sha256": record["native_tbs_sha256"],
            "ui_tbs_sha256": record["ui_tbs_sha256"],
            "pair_tbs_sha256": record["pair_tbs_sha256"],
            "publisher_key_sha256": record["publisher_spki_sha256"],
        }
        if any(report.get(key) != value for key, value in expected_report_fields.items()):
            raise ReleaseError(f"{app_id} signed package bytes conflict with its authorized sequence record")
        if provenance.get("publisher_id") != app["publisher_id"] or provenance.get("app_id") != app_id:
            raise ReleaseError(f"{app_id} provenance identity does not match the independently verified package")
        if provenance.get("release_seq") != app["release_seq"] or provenance.get("source", {}).get("commit") != validated["source_sha"]:
            raise ReleaseError(f"{app_id} provenance does not pin the authorized seq and source SHA")
        if provenance.get("package", {}).get("sha256") != actual_sha256:
            raise ReleaseError(f"{app_id} provenance package digest does not match the fixed package bytes")
        if request["action"] == "simulate":
            if "TEST ONLY" not in provenance.get("artifact_type", "") and "SIMULATION ONLY" not in provenance.get("artifact_type", ""):
                raise ReleaseError("simulation accepts only explicitly non-production signed fixtures")
        elif provenance.get("artifact_type") != "Production signed NEPK v1.1":
            raise ReleaseError(f"{app_id} is not marked as a production-signed package")
        independent = independent_reports.get(app_id)
        if not isinstance(independent, dict) or independent.get("result") != "PASS":
            raise ReleaseError(f"{app_id} lacks a passing independent NEPK verification report")
        for name in ("package_sha256", "native_tbs_sha256", "ui_tbs_sha256", "pair_tbs_sha256", "publisher_key_sha256", "release_seq", "app_id", "publisher_id"):
            if independent.get(name) != report.get(name):
                raise ReleaseError(f"{app_id} independent verification differs at {name}")
        plan_apps.append({
            **app,
            "package_path": str(package_path.resolve()),
            "package_sha256": actual_sha256,
            "package_len": len(package),
            "publisher_spki_sha256": report["publisher_key_sha256"],
            "native_tbs_sha256": report["native_tbs_sha256"],
            "ui_tbs_sha256": report["ui_tbs_sha256"],
            "pair_tbs_sha256": report["pair_tbs_sha256"],
            "native_signature_sha256": report["native_signature_sha256"],
            "ui_signature_sha256": report["ui_signature_sha256"],
            "pair_signature_sha256": report["pair_signature_sha256"],
        })
    plan_apps.sort(key=lambda item: item["app_id"])
    digest_input = {
        "tag": validated["tag"],
        "batch_version": validated["batch_version"],
        "source_sha": validated["source_sha"],
        "request_id": validated["request_id"],
        "authorization_ref": validated["authorization_ref"],
        "apps": [{key: value for key, value in app.items() if key != "package_path"} for app in plan_apps],
    }
    request_sha256 = canonical_json_sha256(digest_input)
    title = f"NE30x Apps {validated['batch_version']}"
    notes_lines = [
        f"# {title}",
        "",
        *( ["SIMULATION ONLY: no production signer or public Release was used.", ""] if validated["action"] == "simulate" else [] ),
        f"Release batch: `{validated['batch_version']}`",
        f"Source SHA: `{validated['source_sha']}`",
        f"Authorization request ID: `{validated['request_id']}`",
        f"Release plan SHA-256: `{request_sha256}`",
        "",
    ]
    for app in plan_apps:
        notes_lines.extend([
            f"## {app['app_id']}",
            "",
            f"- Asset: `{app['asset_name']}`",
            f"- Native v4 version: `{'.'.join(map(str, app['native_version']))}`",
            f"- NEUI v1 version: `{'.'.join(map(str, app['ui_version']))}`",
            f"- Pair release_seq: `{app['release_seq']}`",
            f"- Package SHA-256: `{app['package_sha256']}`",
            f"- Publisher SPKI SHA-256: `{app['publisher_spki_sha256']}`",
            f"- Source SHA: `{validated['source_sha']}`",
            f"- Compatibility: {_markdown_value(app['compatibility'])}",
            "",
        ])
    return {
        "version": 1,
        "action": validated["action"],
        "tag": validated["tag"],
        "title": title,
        "batch_version": validated["batch_version"],
        "source_sha": validated["source_sha"],
        "request_id": validated["request_id"],
        "authorization_ref": validated["authorization_ref"],
        "sequence_ledger_sha256": validated["ledger_sha256"],
        "release_plan_sha256": request_sha256,
        "release_notes": "\n".join(notes_lines).rstrip() + "\n",
        "apps": plan_apps,
    }


def _validate_plan(plan: dict) -> None:
    if not isinstance(plan, dict) or plan.get("version") != 1 or not isinstance(plan.get("apps"), list) or not plan["apps"]:
        raise ReleaseError("release plan is malformed")
    if plan.get("tag") != f"v{plan.get('batch_version')}":
        raise ReleaseError("release plan tag does not match the repository batch version")
    if plan.get("release_plan_sha256") != _plan_digest(plan):
        raise ReleaseError("release plan digest is invalid")


def _plan_digest(plan: dict) -> str:
    return canonical_json_sha256({
        "tag": plan["tag"],
        "batch_version": plan["batch_version"],
        "source_sha": plan["source_sha"],
        "request_id": plan["request_id"],
        "authorization_ref": plan["authorization_ref"],
        "apps": [{key: value for key, value in app.items() if key != "package_path"} for app in plan["apps"]],
    })


def _verify_release_assets(plan: dict, release: dict, client) -> tuple[int, int]:
    if release.get("tag_name") != plan["tag"] or release.get("name") != plan["title"]:
        raise ReleaseError("existing Release tag or name conflicts with this request")
    if release.get("body") != plan["release_notes"]:
        raise ReleaseError("existing Release notes conflict with this request")
    assets = release.get("assets")
    if not isinstance(assets, list) or any(not isinstance(asset, dict) for asset in assets):
        raise ReleaseError("existing Release asset list is unreadable")
    expected = {app["asset_name"]: app for app in plan["apps"]}
    names = [asset.get("name") for asset in assets if isinstance(asset, dict)]
    if any(not isinstance(name, str) for name in names) or len(names) != len(set(names)) or any(name not in expected for name in names):
        raise ReleaseError("existing Release contains duplicate or unexpected assets")
    count = len(names)
    if count not in {0, len(expected)}:
        raise ReleaseError("existing Release has a partial asset set")
    for asset in assets:
        app = expected[asset["name"]]
        data = client.download_asset(asset)
        if hashlib.sha256(data).hexdigest() != app["package_sha256"] or len(data) != app["package_len"]:
            raise ReleaseError("existing Release asset bytes conflict with the verified package")
    return count, len(expected)


def publish_release(plan: dict, client, *, action: str, authorized: bool, simulation: bool = False) -> dict:
    _validate_plan(plan)
    if action not in {"draft", "publish"}:
        raise ReleaseError("release action is missing or differs from the authorized request")
    if not authorized and not simulation:
        raise ReleaseError("release request is not authorized by the protected production job")
    if simulation:
        if plan.get("action") != "simulate" or getattr(client, "simulation_only", False) is not True:
            raise ReleaseError("simulation requires an in-memory Release adapter and a simulation-only plan")
    elif action != plan.get("action"):
        raise ReleaseError("release action is missing or differs from the authorized request")
    tag_ref = client.get_tag(plan["tag"])
    release = client.get_release_by_tag(plan["tag"])
    if release is None and tag_ref is not None:
        raise ReleaseError("tag already exists without a matching Release; refusing to attach or overwrite it")
    if release is None and action == "publish":
        raise ReleaseError("publish action requires an existing complete draft Release")
    if action == "draft" and release is not None and release.get("draft") is False:
        raise ReleaseError("matching Release is already published; a draft request cannot alter it")
    created = False
    if release is None:
        release = client.create_draft_release(plan)
        created = True
        tag_ref = client.get_tag(plan["tag"])
        if tag_ref is None or client.tag_commit(tag_ref) != plan["source_sha"]:
            raise ReleaseError("new draft Release tag does not point at the accepted source SHA")
    elif client.tag_commit(tag_ref) != plan["source_sha"]:
        raise ReleaseError("existing Release tag points at a different source SHA")
    existing_count, expected_count = _verify_release_assets(plan, release, client)
    if release.get("draft") is False and existing_count != expected_count:
        raise ReleaseError("published Release is incomplete; refusing to modify public assets")
    if existing_count == 0:
        if action == "publish":
            raise ReleaseError("publish action requires a complete draft asset set")
        for app in plan["apps"]:
            data = Path(app["package_path"]).read_bytes()
            if hashlib.sha256(data).hexdigest() != app["package_sha256"]:
                raise ReleaseError("package bytes changed after release-plan verification")
            client.upload_asset(release, app["asset_name"], data)
        release = client.get_release_by_tag(plan["tag"])
        existing_count, expected_count = _verify_release_assets(plan, release, client)
    if existing_count != expected_count:
        raise ReleaseError("Release is incomplete; public publication is forbidden")
    if action == "draft":
        return {"result": "DRAFT_READY", "tag": plan["tag"], "release_id": release["id"], "created": created}
    if release.get("draft") is True:
        client.publish_release(release)
        release = client.get_release_by_tag(plan["tag"])
        if release is None or release.get("draft") is not False:
            raise ReleaseError("GitHub did not confirm the complete Release as published")
        count, total = _verify_release_assets(plan, release, client)
        if count != total:
            raise ReleaseError("published Release lost a verified asset")
        return {"result": "PUBLISHED", "tag": plan["tag"], "release_id": release["id"], "created": created}
    return {"result": "IDEMPOTENT", "tag": plan["tag"], "release_id": release["id"], "created": False}


class GitHubReleaseClient:
    def __init__(self, repository: str, token: str, api_url: str = "https://api.github.com"):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ReleaseError("repository must be owner/name")
        if not token:
            raise ReleaseError("GitHub token is unavailable")
        self.repository = repository
        self.token = token
        self.api_url = api_url.rstrip("/")

    def _request(self, method: str, url: str, payload=None, accept: str = "application/vnd.github+json"):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(url, data=data, method=method)
        request.add_header("Accept", accept)
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("X-GitHub-Api-Version", "2026-03-10")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            opener = urllib.request.build_opener(_StripAuthRedirectHandler())
            with opener.open(request, timeout=30) as response:
                body = response.read()
                if not body:
                    return None
                if "json" in response.headers.get("Content-Type", ""):
                    return json.loads(body)
                return body
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise ReleaseError(f"GitHub API {method} failed with HTTP {error.code}") from error
        except (OSError, json.JSONDecodeError) as error:
            raise ReleaseError(f"GitHub API {method} failed") from error

    def _repo_url(self, suffix: str) -> str:
        return f"{self.api_url}/repos/{self.repository}/{suffix}"

    def get_tag(self, tag: str):
        return self._request("GET", self._repo_url(f"git/ref/tags/{urllib.parse.quote(tag, safe='')}"))

    def tag_commit(self, reference: dict) -> str | None:
        if not isinstance(reference, dict):
            return None
        obj = reference.get("object")
        if not isinstance(obj, dict):
            return None
        if obj.get("type") == "commit":
            return obj.get("sha")
        if obj.get("type") != "tag":
            return None
        tag_sha = obj.get("sha")
        if not isinstance(tag_sha, str) or COMMIT_PATTERN.fullmatch(tag_sha) is None:
            return None
        tag = self._request("GET", self._repo_url(f"git/tags/{tag_sha}"))
        target = tag.get("object") if isinstance(tag, dict) else None
        return target.get("sha") if isinstance(target, dict) and target.get("type") == "commit" else None

    def get_release_by_tag(self, tag: str):
        return self._request("GET", self._repo_url(f"releases/tags/{urllib.parse.quote(tag, safe='')}"))

    def create_draft_release(self, plan: dict):
        result = self._request("POST", self._repo_url("releases"), {
            "tag_name": plan["tag"],
            "target_commitish": plan["source_sha"],
            "name": plan["title"],
            "body": plan["release_notes"],
            "draft": True,
            "prerelease": False,
        })
        if not isinstance(result, dict):
            raise ReleaseError("GitHub did not return the created draft Release")
        return result

    def upload_asset(self, release: dict, name: str, data: bytes):
        upload_url = release.get("upload_url", "").split("{", 1)[0]
        release_id = release.get("id")
        if not upload_url or isinstance(release_id, bool) or not isinstance(release_id, int) or release_id < 1:
            raise ReleaseError("draft Release has no asset upload URL")
        parsed = urllib.parse.urlsplit(upload_url)
        api_host = urllib.parse.urlsplit(self.api_url).hostname
        expected_path = f"/repos/{self.repository}/releases/{release_id}/assets".lower()
        if parsed.scheme != "https" or parsed.hostname not in {api_host, "uploads.github.com"} or parsed.port not in {None, 443} or parsed.username or parsed.password or parsed.query or parsed.fragment or not parsed.path.lower().endswith(expected_path):
            raise ReleaseError("draft Release asset upload URL is outside the expected GitHub endpoint")
        url = f"{upload_url}?{urllib.parse.urlencode({'name': name})}"
        request = urllib.request.Request(url, data=data, method="POST")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("X-GitHub-Api-Version", "2026-03-10")
        request.add_header("Content-Type", "application/octet-stream")
        try:
            opener = urllib.request.build_opener(_StripAuthRedirectHandler())
            with opener.open(request, timeout=120) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            raise ReleaseError(f"GitHub asset upload failed with HTTP {error.code}") from error
        except (OSError, json.JSONDecodeError) as error:
            raise ReleaseError("GitHub asset upload failed") from error

    def download_asset(self, asset: dict) -> bytes:
        asset_id = asset.get("id")
        if isinstance(asset_id, bool) or not isinstance(asset_id, int) or asset_id < 1:
            raise ReleaseError("GitHub Release asset ID is malformed")
        result = self._request(
            "GET",
            self._repo_url(f"releases/assets/{asset_id}"),
            accept="application/octet-stream",
        )
        if not isinstance(result, bytes):
            raise ReleaseError("GitHub Release asset could not be downloaded for byte verification")
        return result

    def publish_release(self, release: dict):
        result = self._request("PATCH", self._repo_url(f"releases/{release['id']}"), {"draft": False})
        if not isinstance(result, dict):
            raise ReleaseError("GitHub did not confirm Release publication")
        return result


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    env_parser = commands.add_parser("check-environment")
    env_parser.add_argument("--environment", required=True, type=Path)
    env_parser.add_argument("--branch-policies", required=True, type=Path)
    preflight_parser = commands.add_parser("preflight")
    preflight_parser.add_argument("--request", required=True, type=Path)
    preflight_parser.add_argument("--source-sha", required=True)
    preflight_parser.add_argument("--action", required=True, choices=("draft", "publish"))
    preflight_parser.add_argument("--ledger-sha256")
    preflight_parser.add_argument("--structural-only", action="store_true")
    execute_parser = commands.add_parser("execute")
    execute_parser.add_argument("--request", required=True, type=Path)
    execute_parser.add_argument("--package", required=True, type=Path)
    execute_parser.add_argument("--provenance", required=True, type=Path)
    execute_parser.add_argument("--independent-report", required=True, type=Path)
    execute_parser.add_argument("--spki-der", required=True, type=Path)
    execute_parser.add_argument("--source-sha", required=True)
    execute_parser.add_argument("--action", required=True, choices=("draft", "publish"))
    execute_parser.add_argument("--ledger-sha256", required=True)
    execute_parser.add_argument("--repository", required=True)
    args = parser.parse_args()
    try:
        if args.command == "check-environment":
            validate_environment_configuration(_read_json(args.environment), _read_json(args.branch_policies))
            print(json.dumps({"result": "PASS", "environment": "production", "branch": "main"}, sort_keys=True))
            return 0
        request = _read_json(args.request)
        if args.command == "execute":
            if not isinstance(request, dict) or request.get("action") != args.action:
                raise ReleaseError("release request action does not match the protected job action")
            apps = request.get("apps")
            if not isinstance(apps, list) or len(apps) != 1 or not isinstance(apps[0], dict) or apps[0].get("app_id") != "line-crossing":
                raise ReleaseError("this production builder supports only the current line-crossing App")
            publisher_id = apps[0].get("publisher_id")
            if not isinstance(publisher_id, str):
                raise ReleaseError("release request publisher identity is malformed")
            spki = args.spki_der.read_bytes()
            plan = build_release_plan(
                request,
                {"line-crossing": args.package},
                {"line-crossing": args.provenance},
                {publisher_id: spki},
                {"line-crossing": _read_json(args.independent_report)},
                expected_source_sha=args.source_sha,
                expected_ledger_sha256=args.ledger_sha256,
            )
            client = GitHubReleaseClient(args.repository, os.environ.get("GITHUB_TOKEN", ""))
            result = publish_release(plan, client, action=args.action, authorized=True)
            print(json.dumps(result, sort_keys=True))
            return 0
        if args.structural_only:
            if args.ledger_sha256 is not None:
                raise ReleaseError("structural-only preflight cannot accept a trusted ledger pin")
            ledger_digest = canonical_json_sha256(request.get("sequence_ledger", {}))
            pin_result = "STRUCTURAL_ONLY"
        else:
            if args.ledger_sha256 is None:
                raise ReleaseError("trusted sequence-ledger pin is required")
            ledger_digest = args.ledger_sha256
            pin_result = "PINNED"
        validated = validate_release_request(
            request,
            expected_source_sha=args.source_sha,
            expected_action=args.action,
            expected_ledger_sha256=ledger_digest,
        )
        print(json.dumps({
            "result": "PASS",
            "ledger_validation": pin_result,
            "tag": validated["tag"],
            "source_sha": validated["source_sha"],
            "apps": [app["app_id"] for app in validated["apps"]],
            "sequence_ledger_sha256": validated["ledger_sha256"],
        }, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, NePKError) as error:
        print(json.dumps({"result": "REJECTED", "detail": str(error)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
