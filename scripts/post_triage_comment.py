#!/usr/bin/env python3
"""Post an Endor Labs triage comment on a pull request.

Fetches open CI-blocking and CI-warning findings from the Endor Labs API,
builds a sorted, linked table with a hidden UUID map, and posts it as a PR
comment. Developers can reply with /endor fp or /endor accept-risk commands
to triage findings without leaving the PR.

Required:
    ENDOR_NAMESPACE  - Your Endor Labs tenant namespace.

Everything else is auto-detected from the standard GitHub Actions environment
(GITHUB_REPOSITORY, GITHUB_TOKEN, GITHUB_EVENT_PATH). Set the corresponding
environment variable explicitly to override any auto-detected value:
    GH_TOKEN           - GitHub token (defaults to GITHUB_TOKEN)
    REPO               - owner/repo (defaults to GITHUB_REPOSITORY)
    PR_NUMBER          - PR number (auto-detected from event payload or GITHUB_REF)
    ENDOR_PROJECT_UUID - Project UUID (auto-detected from repo name via Endor API)

Authentication against Endor Labs:
    GitHub Actions OIDC: automatic when GITHUB_ACTIONS=true (no secrets needed).
    API key:             set ENDOR_API_KEY as a CI secret.
    Key pair:            set ENDOR_KEYID and ENDOR_PRIVATE_KEY as CI secrets.
"""

import json
import os
import re
import subprocess
import sys
import tempfile


PLATFORM_URL = "https://app.endorlabs.com"

SEVERITY_LABEL = {
    "FINDING_LEVEL_CRITICAL": "🔴&nbsp;Critical",
    "FINDING_LEVEL_HIGH": "🟠&nbsp;High",
    "FINDING_LEVEL_MEDIUM": "🟡&nbsp;Medium",
    "FINDING_LEVEL_LOW": "🔵&nbsp;Low",
}

SEVERITY_ORDER = {
    "FINDING_LEVEL_CRITICAL": 0,
    "FINDING_LEVEL_HIGH": 1,
    "FINDING_LEVEL_MEDIUM": 2,
    "FINDING_LEVEL_LOW": 3,
}

COMMENT_HEADER = "## :shield: Endor Labs — Triage Findings"

_VULN_PREFIX_RE = re.compile(r"^((?:GHSA|CVE)-[\w-]+):\s*")


# ── Environment helpers ───────────────────────────────────────────────────────

def _github_event() -> dict:
    """Load the GitHub Actions event payload, or return an empty dict."""
    path = os.environ.get("GITHUB_EVENT_PATH", "")
    if not path:
        return {}
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}


def _resolve(env_var: str, *fallbacks: str) -> str:
    """Return the first non-empty value: explicit env var, then fallbacks."""
    val = os.environ.get(env_var, "").strip()
    if val:
        return val
    for fb in fallbacks:
        fb = fb.strip()
        if fb:
            return fb
    return ""


def _detect_pr_number() -> str:
    """Detect the PR number from the GitHub Actions environment."""
    # From the pull_request event payload
    event = _github_event()
    pr_num = str(event.get("pull_request", {}).get("number", "")).strip()
    if pr_num:
        return pr_num
    # From GITHUB_REF: refs/pull/123/merge
    ref = os.environ.get("GITHUB_REF", "")
    m = re.match(r"refs/pull/(\d+)/", ref)
    if m:
        return m.group(1)
    return ""


# ── endorctl helpers ──────────────────────────────────────────────────────────

def _run(cmd: list[str]) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def _auth_flags() -> list[str]:
    """Return endorctl auth flags for the current environment."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return ["--enable-github-action-token"]
    return []


def fetch_project_uuid(namespace: str, repo: str) -> str:
    """Look up the Endor Labs project UUID from the GitHub repository name."""
    github_url = f"https://github.com/{repo}.git"
    cmd = [
        "endorctl", "api", "list",
        *_auth_flags(),
        f"--namespace={namespace}",
        "--resource=Project",
        "--output-type=json",
        f"--filter=meta.name==\"{github_url}\"",
    ]
    rc, stdout, stderr = _run(cmd)
    if rc != 0:
        print(f"Warning: unable to fetch project UUID: {stderr.strip()}", file=sys.stderr)
        return ""
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return ""
    objects = data.get("list", {}).get("objects", [])
    return objects[0].get("uuid", "") if objects else ""


def fetch_findings(namespace: str, project_uuid: str) -> list[dict]:
    """Fetch open CI-blocking and CI-warning findings scoped to this project."""
    filter_expr = (
        f'spec.finding_tags contains ["FINDING_TAGS_CI_BLOCKER","FINDING_TAGS_CI_WARNING"]'
        f' and spec.dismiss==false'
        f' and spec.project_uuid=="{project_uuid}"'
    )
    cmd = [
        "endorctl", "api", "list",
        *_auth_flags(),
        f"--namespace={namespace}",
        "--resource=Finding",
        "--output-type=json",
        "--page-size=50",
        f"--filter={filter_expr}",
    ]
    rc, stdout, stderr = _run(cmd)
    if rc != 0:
        print(f"Warning: endorctl api list failed: {stderr.strip()}", file=sys.stderr)
        return []
    try:
        data = json.loads(stdout)
    except json.JSONDecodeError as exc:
        print(f"Warning: unable to parse findings JSON: {exc}", file=sys.stderr)
        return []
    return data.get("list", {}).get("objects", [])


# ── URL helpers ───────────────────────────────────────────────────────────────

def finding_url(namespace: str, finding_uuid: str) -> str:
    """Return the Endor Labs platform URL for a single finding."""
    return f"{PLATFORM_URL}/t/{namespace}/findings/{finding_uuid}"


def pr_scan_url(namespace: str, project_uuid: str) -> str:
    """Return the Endor Labs platform URL for the project PR scans page."""
    return f"{PLATFORM_URL}/t/{namespace}/projects/{project_uuid}/versions/default/pr-runs"


def advisory_url(vuln_id: str) -> str:
    """Return the public advisory URL for a GHSA or CVE identifier."""
    if vuln_id.upper().startswith("GHSA-"):
        return f"https://github.com/advisories/{vuln_id}"
    if vuln_id.upper().startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{vuln_id}"
    return ""


# ── Finding helpers ───────────────────────────────────────────────────────────

def extract_vuln_id(obj: dict) -> str:
    """Extract the vuln ID from the finding."""
    vuln_id = obj.get("spec", {}).get("vuln_id", "").strip()
    if vuln_id:
        return vuln_id
    extra_key = obj.get("spec", {}).get("extra_key", "").strip()
    if extra_key and re.match(r"^(GHSA|CVE)-", extra_key):
        return extra_key
    desc = obj.get("meta", {}).get("description", "")
    m = _VULN_PREFIX_RE.match(desc)
    if m:
        return m.group(1)
    return ""


def clean_description(description: str, vuln_id: str) -> str:
    """Strip the leading vuln-id prefix from a description if present."""
    if vuln_id and description.startswith(vuln_id + ": "):
        return description[len(vuln_id) + 2:]
    m = _VULN_PREFIX_RE.match(description)
    if m:
        return description[m.end():]
    return description


def sort_key(obj: dict) -> tuple:
    """Return a sort key: (severity_rank, package_name)."""
    level = obj.get("spec", {}).get("level", "")
    rank = SEVERITY_ORDER.get(level, 99)
    pkg = obj.get("spec", {}).get("target_dependency_package_name", "")
    return (rank, pkg.lower())


# ── Comment builder ───────────────────────────────────────────────────────────

def build_comment(
    findings: list[dict],
    namespace: str,
    project_uuid: str,
) -> tuple[str, dict]:
    """Build the PR comment body and a number-to-UUID mapping."""
    uuid_map: dict[str, str] = {}
    lines: list[str] = []

    scan_link = pr_scan_url(namespace, project_uuid)

    lines.append(COMMENT_HEADER)
    lines.append("")
    lines.append(f'<a href="{scan_link}" target="_blank">View PR scans on Endor Labs →</a>')
    lines.append("")
    lines.append("Reply with a command to triage findings in bulk:")
    lines.append("")
    lines.append("| Command | Effect |")
    lines.append("|---------|--------|")
    lines.append("| `/endor fp 1,2` | Mark findings 1 and 2 as **false positive** |")
    lines.append("| `/endor accept-risk 3` | Mark finding 3 as **accepted risk** |")
    lines.append("")
    lines.append("<details><summary>Optional flags</summary>")
    lines.append("")
    lines.append("| Flag | Description | Example |")
    lines.append("|------|-------------|---------|")
    lines.append('| `--comment="..."` | Add a note explaining the triage decision | `/endor fp 1 --comment="Not reachable in prod"` |')
    lines.append("| `--expires=YYYY-MM-DD` | Auto-expire the ignore entry on this date | `/endor fp 1 --expires=2026-12-31` |")
    lines.append("| `--expire-if-fix` | Auto-expire when a fix becomes available | `/endor accept-risk 2 --expire-if-fix` |")
    lines.append("")
    lines.append("Flags can be combined: `/endor fp 1,2 --comment=\"Low risk\" --expires=2026-06-30 --expire-if-fix`")
    lines.append("")
    lines.append("</details>")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("### Findings")
    lines.append("")
    lines.append("| Finding | Severity | Package | Vulnerability |")
    lines.append("|---------|----------|---------|---------------|")

    for i, obj in enumerate(sorted(findings, key=sort_key), start=1):
        uuid = obj.get("uuid", "")
        description = obj.get("meta", {}).get("description", "Unknown finding")
        level = obj.get("spec", {}).get("level", "")
        dep = obj.get("spec", {}).get("target_dependency_package_name", "")
        vuln_id = extract_vuln_id(obj)

        uuid_map[str(i)] = uuid
        severity_cell = SEVERITY_LABEL.get(level, "⚪ Unknown")
        desc = clean_description(description, vuln_id).replace("|", "\\|")
        dep_cell = f"`{dep}`" if dep else "—"

        if uuid:
            f_url = finding_url(namespace, uuid)
            num_cell = f'<a href="{f_url}" target="_blank"><strong>{i}</strong></a>'
        else:
            num_cell = f"**{i}**"

        adv_url = advisory_url(vuln_id) if vuln_id else ""
        if vuln_id and adv_url:
            vuln_cell = f'<a href="{adv_url}" target="_blank">{vuln_id}</a> {desc}'
        elif vuln_id:
            vuln_cell = f"`{vuln_id}` {desc}"
        else:
            vuln_cell = desc

        lines.append(f"| {num_cell} | {severity_cell} | {dep_cell} | {vuln_cell} |")

    lines.append("")
    lines.append(f"<!-- endor-findings-map\n{json.dumps(uuid_map)}\n-->")

    return "\n".join(lines), uuid_map


# ── PR comment ────────────────────────────────────────────────────────────────

def post_comment(pr_number: str, repo: str, body: str) -> None:
    """Post a comment on the pull request via the gh CLI."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as fh:
        fh.write(body)
        tmp_path = fh.name
    try:
        rc, _, stderr = _run(
            ["gh", "pr", "comment", pr_number, "--repo", repo, "--body-file", tmp_path]
        )
        if rc != 0:
            print(f"Error posting PR comment: {stderr.strip()}", file=sys.stderr)
            sys.exit(1)
    finally:
        os.unlink(tmp_path)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    """Entry point."""
    namespace = os.environ.get("ENDOR_NAMESPACE", "").strip()
    if not namespace:
        print("Error: ENDOR_NAMESPACE is required.", file=sys.stderr)
        sys.exit(1)

    repo = _resolve("REPO", os.environ.get("GITHUB_REPOSITORY", ""))
    gh_token = _resolve("GH_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
    pr_number = _resolve("PR_NUMBER", _detect_pr_number())

    if not repo:
        print("Error: could not determine repository. Set REPO=owner/repo.", file=sys.stderr)
        sys.exit(1)
    if not pr_number:
        print("Error: could not determine PR number. Set PR_NUMBER.", file=sys.stderr)
        sys.exit(1)
    if gh_token:
        os.environ.setdefault("GH_TOKEN", gh_token)

    project_uuid = _resolve("ENDOR_PROJECT_UUID", "")
    if not project_uuid:
        print(f"ENDOR_PROJECT_UUID not set — looking up project UUID for {repo}...")
        project_uuid = fetch_project_uuid(namespace, repo)
        if not project_uuid:
            print(
                f"Error: unable to determine project UUID for {repo}. "
                "Set ENDOR_PROJECT_UUID to skip auto-detection.",
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"Resolved project UUID: {project_uuid}")

    findings = fetch_findings(namespace, project_uuid)
    if not findings:
        print("No CI-blocking or CI-warning findings. Skipping triage comment.")
        return

    body, uuid_map = build_comment(findings, namespace, project_uuid)
    print(f"Posting triage comment for {len(uuid_map)} finding(s) on PR #{pr_number}...")
    post_comment(pr_number, repo, body)
    print("Done.")


if __name__ == "__main__":
    main()
