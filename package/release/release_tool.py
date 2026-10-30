import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

VERSION_RE = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")

ADDED_PREFIXES = ("feat",)
FIXED_PREFIXES = ("fix",)
DEFAULT_MAX_COMMITS = 50


class ReleaseToolError(Exception):
    pass


def parse_version(value: str) -> tuple[int, int, int]:
    match = VERSION_RE.match(value or "")
    if match is None:
        raise ReleaseToolError(
            f"version must match vX.Y.Z (semver, no prefix/suffix): got {value!r}")
    return tuple(int(part) for part in match.groups())


def classify_subject(subject: str) -> str:
    head = subject.split(":", 1)[0].split("(", 1)[0].strip().lower()
    if any(head == prefix or head.startswith(prefix + "/")
           for prefix in ADDED_PREFIXES):
        return "Added"
    if head in FIXED_PREFIXES or head.startswith("fix/"):
        return "Fixed"
    return "Changed"


def summarize_commits(subjects: list[str], max_commits: int = DEFAULT_MAX_COMMITS) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {"Added": [], "Fixed": [], "Changed": []}
    kept = 0
    overflow = 0
    for subject in subjects:
        if kept >= max_commits:
            overflow += 1
            continue
        buckets[classify_subject(subject)].append(subject)
        kept += 1
    if overflow:
        buckets["Changed"].append(
            f"... and {overflow} earlier commits (see repository history)")
    return {key: value for key, value in buckets.items() if value}


def render_notes(repo_version: str, provenance: dict, verification: dict,
                 commits: dict[str, list[str]], known_limitations: list[str]) -> str:
    parse_version(repo_version)
    if verification.get("result") != "PASS":
        raise ReleaseToolError(
            f"refusing release notes: verification is "
            f"{verification.get('result')!r}, not PASS")
    package_sha = provenance.get("package", {}).get("sha256")
    package_len = provenance.get("package", {}).get("len")
    if not package_sha or package_len is None:
        raise ReleaseToolError("provenance is missing package sha256/len")
    required_fields = ("app_id", "native_version", "ui_version", "source_commit")
    missing = [field for field in required_fields if not provenance.get(field)]
    if missing:
        raise ReleaseToolError(f"provenance is missing: {', '.join(missing)}")

    lines = [
        f"## line-crossing {repo_version}",
        "",
        "Unsigned NEAPP05 candidate packaged by the repository release pipeline.",
        "",
        "### Package identity",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Repository version | {repo_version} (release batch identity) |",
        f"| App ID | {provenance['app_id']} |",
        f"| Native version | {'.'.join(str(x) for x in provenance['native_version'])} |",
        f"| UI version | {'.'.join(str(x) for x in provenance['ui_version'])} |",
        f"| Package format | {provenance.get('format', 'neapp-v5-unsigned')} |",
        f"| Package size | {package_len} bytes |",
        f"| Package SHA-256 | `{package_sha}` |",
        f"| Source commit | `{provenance['source_commit']}` |",
        f"| Signing | {provenance.get('signing_dependencies', 'none')} |",
        "",
        "Repository version, native version, and UI version are recorded",
        "separately; they are different version lines and may carry equal or",
        "different values.",
        "",
        "### Changes",
        "",
    ]
    if commits:
        for section in ("Added", "Fixed", "Changed"):
            entries = commits.get(section)
            if not entries:
                continue
            lines.append(f"#### {section}")
            lines.append("")
            lines.extend(f"- {subject}" for subject in entries)
            lines.append("")
    else:
        lines.append("No recorded commit history for this range.")
        lines.append("")

    host_policy = provenance.get("host_policy", {})
    host_caps = host_policy.get("host_caps", "unrecorded")
    if isinstance(host_caps, int):
        host_caps = f"0x{host_caps:x}"
    lines.extend([
        "### Compatibility",
        "",
        f"- Host caps: `{host_caps}`",
        f"- Resource quotas: event_max={host_policy.get('event_max', 'unrecorded')},"
        f" state_quota={host_policy.get('state_quota', 'unrecorded')},"
        f" control_max={host_policy.get('control_max', 'unrecorded')},"
        f" snapshot_max={host_policy.get('snapshot_max', 'unrecorded')},"
        f" report_max={host_policy.get('report_max', 'unrecorded')}",
        f"- Verification boundary: `{provenance.get('verification_boundary', 'unrecorded')}`",
        "- Requires device firmware with unsigned NEAPP05 admission enabled.",
        "",
        "### Verification",
        "",
        f"- Independent verifier result: **{verification['result']}**",
        "- Verification report: attached as `*.verification.json`",
        "- Build provenance: attached as `*.provenance.json`",
        "",
        "### Known limitations",
        "",
    ])
    if known_limitations:
        lines.extend(f"- {item}" for item in known_limitations)
    else:
        lines.append("- None recorded.")
    lines.append("")
    return "\n".join(lines)


def load_known_limitations(path: Path | None) -> list[str]:
    if path is None or not path.is_file():
        return []
    items: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith(">"):
            continue
        if line.startswith("- "):
            items.append(line[2:].strip())
        elif items:
            items[-1] = f"{items[-1]} {line}"
        else:
            items.append(line)
    return items


def gh(args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(["gh", *args], capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def check_conflicts(repo_version: str, repo_slug: str) -> list[str]:
    parse_version(repo_version)
    conflicts = []
    code, _ = gh(["api", f"repos/{repo_slug}/git/ref/tags/{repo_version}"])
    if code == 0:
        conflicts.append(f"tag {repo_version} already exists")
    code, body = gh(["api", f"repos/{repo_slug}/releases/tags/{repo_version}"])
    if code == 0:
        conflicts.append(f"release {repo_version} already exists")
    code, body = gh(["api", f"repos/{repo_slug}/releases?per_page=100"])
    if code == 0:
        for release in json.loads(body):
            if release.get("draft") and release.get("tag_name") == repo_version:
                conflicts.append(
                    f"draft release {repo_version} already exists")
                break
    elif "404" not in body:
        raise ReleaseToolError(f"unable to list releases: {body}")
    return conflicts


def create_draft(repo_version: str, target_sha: str, title: str,
                 notes_file: Path, assets: list[Path]) -> str:
    parse_version(repo_version)
    if not notes_file.is_file():
        raise ReleaseToolError(f"notes file missing: {notes_file}")
    for asset in assets:
        if not asset.is_file():
            raise ReleaseToolError(f"asset missing: {asset}")
    code, body = gh([
        "release", "create", repo_version, "--draft", "--target", target_sha,
        "--title", title, "--notes-file", str(notes_file),
        *[str(asset) for asset in assets],
    ])
    if code != 0:
        cleanup_code, cleanup_body = gh(
            ["release", "delete", repo_version, "--yes"])
        detail = f"gh release create failed: {body}"
        if cleanup_code == 0:
            detail += " (partial draft removed)"
        else:
            detail += f" (cleanup failed: {cleanup_body})"
        raise ReleaseToolError(detail)
    return body.strip().splitlines()[-1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="release_tool.py")
    sub = parser.add_subparsers(dest="command", required=True)

    validate = sub.add_parser("validate-version")
    validate.add_argument("--version", required=True)

    notes = sub.add_parser("notes")
    notes.add_argument("--repo-version", required=True)
    notes.add_argument("--provenance", required=True, type=Path)
    notes.add_argument("--verification", required=True, type=Path)
    notes.add_argument("--out", required=True, type=Path)
    notes.add_argument("--known-limitations", type=Path)
    notes.add_argument("--commits-file", type=Path,
                       help="one git subject per line; defaults to no history")

    conflicts = sub.add_parser("check-conflicts")
    conflicts.add_argument("--version", required=True)
    conflicts.add_argument("--repo-slug", required=True)

    draft = sub.add_parser("create-draft")
    draft.add_argument("--version", required=True)
    draft.add_argument("--target-sha", required=True)
    draft.add_argument("--title", required=True)
    draft.add_argument("--notes-file", required=True, type=Path)
    draft.add_argument("--assets", required=True, nargs="+", type=Path)

    args = parser.parse_args(argv)
    try:
        if args.command == "validate-version":
            parse_version(args.version)
            print(f"OK {args.version}")
        elif args.command == "notes":
            provenance = json.loads(args.provenance.read_text(encoding="utf-8"))
            verification = json.loads(
                args.verification.read_text(encoding="utf-8"))
            subjects = []
            if args.commits_file is not None and args.commits_file.is_file():
                subjects = [line.strip() for line in
                            args.commits_file.read_text(encoding="utf-8")
                            .splitlines() if line.strip()]
            text = render_notes(args.repo_version, provenance, verification,
                                summarize_commits(subjects),
                                load_known_limitations(args.known_limitations))
            args.out.write_text(text, encoding="utf-8")
            print(f"notes written: {args.out}")
        elif args.command == "check-conflicts":
            found = check_conflicts(args.version, args.repo_slug)
            if found:
                for conflict in found:
                    print(f"CONFLICT {conflict}", file=sys.stderr)
                return 1
            print(f"no conflicts for {args.version}")
        elif args.command == "create-draft":
            url = create_draft(args.version, args.target_sha, args.title,
                               args.notes_file, args.assets)
            print(url)
    except (ReleaseToolError, OSError, json.JSONDecodeError) as error:
        print(f"ERROR {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
