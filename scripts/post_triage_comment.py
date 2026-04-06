#!/usr/bin/env python3
"""Post an Endor Labs triage comment on a pull request.

Fetches open CI-blocking and CI-warning findings from the Endor Labs API,
builds a numbered list with a hidden UUID map, and posts it as a PR comment.
Developers can then reply with /endor fp or /endor accept-risk commands to
triage findings without leaving the PR.

Required environment variables:
    ENDOR_NAMESPACE  - Endor Labs tenant namespace
    PR_NUMBER        - Pull request number
    REPO             - GitHub repository in owner/repo format
    GH_TOKEN         - GitHub token with pull-requests:write permission

The endorctl binary must be installed and authenticated before this script runs.
"""

import json
import os
import subprocess
import sys
import tempfile


SEVERITY_EMOJI = {
    "FINDING_LEVEL_CRITICAL": "🔴",
    "FINDING_LEVEL_HIGH": "🟠",
    "FINDING_LEVEL_MEDIUM": "🟡",
    "FINDING_LEVEL_LOW": "🔵",
}

COMMENT_HEADER = "## :shield: Endor Labs — Triage Findings"


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
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Warning: endorctl api list failed: {result.stderr.strip()}", file=sys.stderr)
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"Warning: unable to parse findings JSON: {exc}", file=sys.stderr)
        return []

    return data.get("list", {}).get("objects", [])


def build_comment(findings: list[dict]) -> tuple[str, dict]:
    """Build the PR comment body and a number-to-UUID mapping.

    Returns a tuple of (comment_body, uuid_map).
    """
    uuid_map: dict[str, str] = {}
    lines: list[str] = []

    lines.append(COMMENT_HEADER)
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

    for i, obj in enumerate(findings, start=1):
        uuid = obj.get("uuid", "")
        description = obj.get("meta", {}).get("description", "Unknown finding")
        level = obj.get("spec", {}).get("level", "")
        dep = obj.get("spec", {}).get("target_dependency_package_name", "")
        vuln_id = obj.get("spec", {}).get("vuln_id", "")

        uuid_map[str(i)] = uuid
        emoji = SEVERITY_EMOJI.get(level, "⚪")
        vuln_suffix = f" `{vuln_id}`" if vuln_id else ""
        dep_label = f" `{dep}`" if dep else ""
        lines.append(f"**{i}.** {emoji}{dep_label}{vuln_suffix} — {description}")

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
        result = subprocess.run(
            ["gh", "pr", "comment", pr_number, "--repo", repo, "--body-file", tmp_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print(f"Error posting PR comment: {result.stderr.strip()}", file=sys.stderr)
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

    body, uuid_map = build_comment(findings)
    print(f"Posting triage comment for {len(uuid_map)} finding(s) on PR #{pr_number}...")
    post_comment(pr_number, repo, body)
    print("Done.")


if __name__ == "__main__":
    main()
