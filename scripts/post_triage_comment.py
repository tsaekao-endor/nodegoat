#!/usr/bin/env python3
"""Post an Endor Labs triage comment on a pull request.

Fetches open CI-blocking and CI-warning findings from the Endor Labs API,
builds a sorted, linked table with a hidden UUID map, and posts it as a PR
comment. Developers can reply with /endor fp or /endor accept-risk commands
to triage findings without leaving the PR.

Required environment variables:
    ENDOR_NAMESPACE    - Endor Labs tenant namespace
    ENDOR_PROJECT_UUID - Endor Labs project UUID for this repository
    PR_NUMBER          - Pull request number
    REPO               - GitHub repository in owner/repo format
    GH_TOKEN           - GitHub token with pull-requests:write permission

The endorctl binary must be installed and authenticated before this script runs.
"""

import json
import os
import re
import subprocess
import sys
import tempfile


PLATFORM_URL = "https://app.endorlabs.com"


SEVERITY_EMOJI = {
    "FINDING_LEVEL_CRITICAL": "🔴",
    "FINDING_LEVEL_HIGH": "🟠",
    "FINDING_LEVEL_MEDIUM": "🟡",
    "FINDING_LEVEL_LOW": "🔵",
}

SEVERITY_LABEL = {
    "FINDING_LEVEL_CRITICAL": "🔴&nbsp;Critical",
    "FINDING_LEVEL_HIGH": "🟠&nbsp;High",
    "FINDING_LEVEL_MEDIUM": "🟡&nbsp;Medium",
    "FINDING_LEVEL_LOW": "🔵&nbsp;Low",
}

# Lower number = higher priority in sort
SEVERITY_ORDER = {
    "FINDING_LEVEL_CRITICAL": 0,
    "FINDING_LEVEL_HIGH": 1,
    "FINDING_LEVEL_MEDIUM": 2,
    "FINDING_LEVEL_LOW": 3,
}

COMMENT_HEADER = "## :shield: Endor Labs — Triage Findings"

# Matches a leading "GHSA-xxxx-xxxx-xxxx: " or "CVE-YYYY-NNNNN: " prefix
_VULN_PREFIX_RE = re.compile(r"^((?:GHSA|CVE)-[\w-]+):\s*")


def _run(cmd: list[str]) -> tuple[int, str, str]:
    """Run a subprocess and return (returncode, stdout, stderr)."""
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode, result.stdout, result.stderr


def fetch_findings(namespace: str, project_uuid: str) -> list[dict]:
    """Fetch open CI-blocking and CI-warning findings scoped to this project."""
    filter_expr = (
        f'spec.finding_tags contains ["FINDING_TAGS_CI_BLOCKER","FINDING_TAGS_CI_WARNING"]'
        f' and spec.dismiss==false'
        f' and spec.project_uuid=="{project_uuid}"'
    )
    cmd = [
        "endorctl", "api", "list",
        "--enable-github-action-token",
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


def extract_vuln_id(obj: dict) -> str:
    """Extract the vuln ID from the finding, falling back to parsing the description."""
    # Prefer the dedicated field
    vuln_id = obj.get("spec", {}).get("vuln_id", "").strip()
    if vuln_id:
        return vuln_id
    # Also try extra_key which often holds the GHSA
    extra_key = obj.get("spec", {}).get("extra_key", "").strip()
    if extra_key and re.match(r"^(GHSA|CVE)-", extra_key):
        return extra_key
    # Last resort: parse the leading "GHSA-xxxx: " out of description
    desc = obj.get("meta", {}).get("description", "")
    m = _VULN_PREFIX_RE.match(desc)
    if m:
        return m.group(1)
    return ""


def clean_description(description: str, vuln_id: str) -> str:
    """Strip the leading vuln-id prefix from a description if present."""
    if vuln_id and description.startswith(vuln_id + ": "):
        return description[len(vuln_id) + 2:]
    # Strip any generic GHSA/CVE prefix even if we didn't match vuln_id
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


def build_comment(
    findings: list[dict],
    namespace: str,
    project_uuid: str,
) -> tuple[str, dict]:
    """Build the PR comment body and a number-to-UUID mapping.

    Returns a tuple of (comment_body, uuid_map).
    """
    uuid_map: dict[str, str] = {}
    lines: list[str] = []

    scan_link = pr_scan_url(namespace, project_uuid)

    lines.append(COMMENT_HEADER)
    lines.append("")
    lines.append(
        f'<a href="{scan_link}" target="_blank">View PR scans on Endor Labs →</a>'
    )
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

    sorted_findings = sorted(findings, key=sort_key)

    for i, obj in enumerate(sorted_findings, start=1):
        uuid = obj.get("uuid", "")
        description = obj.get("meta", {}).get("description", "Unknown finding")
        level = obj.get("spec", {}).get("level", "")
        dep = obj.get("spec", {}).get("target_dependency_package_name", "")
        vuln_id = extract_vuln_id(obj)

        uuid_map[str(i)] = uuid
        severity_cell = SEVERITY_LABEL.get(level, "⚪ Unknown")

        desc = clean_description(description, vuln_id).replace("|", "\\|")
        dep_cell = f"`{dep}`" if dep else "—"

        # Finding number links to the Endor platform finding page (new tab)
        if uuid:
            f_url = finding_url(namespace, uuid)
            num_cell = f'<a href="{f_url}" target="_blank"><strong>{i}</strong></a>'
        else:
            num_cell = f"**{i}**"

        # Vuln ID links to public advisory; combined with description in one cell
        adv_url = advisory_url(vuln_id) if vuln_id else ""
        if vuln_id and adv_url:
            vuln_link = f'<a href="{adv_url}" target="_blank">{vuln_id}</a>'
            vuln_cell = f"{vuln_link} {desc}"
        elif vuln_id:
            vuln_cell = f"`{vuln_id}` {desc}"
        else:
            vuln_cell = desc

        lines.append(f"| {num_cell} | {severity_cell} | {dep_cell} | {vuln_cell} |")

    # Hidden machine-readable UUID map consumed by handle_triage_command.py
    lines.append("")
    lines.append(f"<!-- endor-findings-map\n{json.dumps(uuid_map)}\n-->")

    return "\n".join(lines), uuid_map


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


def main() -> None:
    """Entry point."""
    namespace = os.environ["ENDOR_NAMESPACE"]
    project_uuid = os.environ["ENDOR_PROJECT_UUID"]
    pr_number = os.environ["PR_NUMBER"]
    repo = os.environ["REPO"]

    findings = fetch_findings(namespace, project_uuid)
    if not findings:
        print("No CI-blocking or CI-warning findings found. Skipping triage comment.")
        return

    body, uuid_map = build_comment(findings, namespace, project_uuid)
    print(f"Posting triage comment for {len(uuid_map)} finding(s) on PR #{pr_number}...")
    post_comment(pr_number, repo, body)
    print("Done.")


if __name__ == "__main__":
    main()
