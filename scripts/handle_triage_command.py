#!/usr/bin/env python3
"""Handle /endor triage commands posted in pull request comments.

Parses /endor fp and /endor accept-risk commands, maps the referenced finding
numbers to UUIDs from the hidden findings map in the triage comment, runs
endorctl ignore for each finding, commits the updated .endorignore.yaml to the
PR branch, and replies with a summary comment.

Supported command syntax:
    /endor fp 1,2
    /endor accept-risk 3
    /endor fp 1 --comment="Not applicable in our environment"
    /endor fp 1,2 --expires=2026-12-31
    /endor accept-risk 3 --expire-if-fix
    /endor fp 1 --comment="Low risk" --expires=2026-06-30 --expire-if-fix

Required environment variables:
    ENDOR_NAMESPACE  - Endor Labs tenant namespace
    PR_NUMBER        - Pull request number
    REPO             - GitHub repository in owner/repo format
    GH_TOKEN         - GitHub token with pull-requests:write and contents:write
    COMMENT_BODY     - Body text of the triggering PR comment
    COMMENTER        - GitHub username of the person who posted the command

Authentication (one of the following):
    GitHub Actions OIDC (automatic when GITHUB_ACTIONS=true):
        No extra configuration needed. endorctl uses the OIDC token automatically.
    API key:
        ENDOR_API_KEY  - Endor Labs API key (set in your CI secrets)
    Service account key pair:
        ENDOR_KEYID      - Key ID
        ENDOR_PRIVATE_KEY - Private key (base64-encoded or PEM)

The endorctl binary must be on PATH before this script runs.
"""

import json
import os
import re
import subprocess
import sys
import tempfile


IGNORE_FILE = ".endorignore.yaml"

# Maps command keyword to endorctl --reason value
COMMAND_MAP = {
    "fp": "false-positive",
    "accept-risk": "risk-accepted",
}

COMMAND_LABELS = {
    "fp": "false positive",
    "accept-risk": "accepted risk",
}

# Matches YYYY-MM-DD
_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def _endorctl_auth_flags() -> list[str]:
    """Return the appropriate endorctl auth flags for the current CI environment.

    In GitHub Actions, uses keyless OIDC (no secrets needed).
    In all other environments, endorctl picks up credentials from environment
    variables (ENDOR_API_KEY, ENDOR_KEYID/ENDOR_PRIVATE_KEY) automatically.
    """
    if os.environ.get("GITHUB_ACTIONS") == "true":
        return ["--enable-github-action-token"]
    return []


def parse_command(comment_body: str) -> tuple[str | None, list[str], dict]:
    """Parse a triage command and optional flags from a PR comment body.

    Returns a tuple of (command_key, list_of_finding_numbers, options).
    options may contain: comment (str), expires (str), expire_if_fix (bool).
    command_key is one of the keys in COMMAND_MAP, or None if no command found.
    """
    command_key = None
    numbers: list[str] = []

    for key in COMMAND_MAP:
        # Capture the numbers portion — stops at first '--' or end of line
        match = re.search(
            rf"/endor {re.escape(key)}\s+([\d,\s]+?)(?:\s+--|$)",
            comment_body,
        )
        if match:
            command_key = key
            raw = match.group(1)
            numbers = [n.strip() for n in re.split(r"[,\s]+", raw) if n.strip().isdigit()]
            break

    if not command_key:
        return None, [], {}

    options: dict = {}

    # --comment="..." or --comment=...
    comment_match = re.search(r'--comment=["\']?([^"\']+)["\']?', comment_body)
    if comment_match:
        options["comment"] = comment_match.group(1).strip()

    # --expires=YYYY-MM-DD
    expires_match = re.search(r"--expires=(\S+)", comment_body)
    if expires_match:
        date_val = expires_match.group(1).strip()
        if _DATE_RE.match(date_val):
            options["expires"] = date_val
        else:
            print(
                f"Warning: --expires value '{date_val}' is not a valid YYYY-MM-DD date. Ignoring.",
                file=sys.stderr,
            )

    # --expire-if-fix (boolean flag)
    if "--expire-if-fix" in comment_body:
        options["expire_if_fix"] = True

    return command_key, numbers, options


def fetch_uuid_map(pr_number: str, repo: str) -> dict[str, str]:
    """Extract the hidden UUID map from the triage comment on the PR."""
    result = subprocess.run(
        [
            "gh", "api",
            f"repos/{repo}/issues/{pr_number}/comments",
            "--jq", ".[].body",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Error fetching PR comments: {result.stderr.strip()}", file=sys.stderr)
        return {}

    for block in result.stdout.split("\n\n"):
        map_match = re.search(
            r"<!-- endor-findings-map\n(\{.*?\})\n-->",
            block,
            re.DOTALL,
        )
        if map_match:
            try:
                return json.loads(map_match.group(1))
            except json.JSONDecodeError as exc:
                print(f"Warning: unable to parse UUID map: {exc}", file=sys.stderr)
                return {}

    return {}


def run_ignore(
    uuid: str,
    namespace: str,
    reason: str,
    commenter: str,
    options: dict,
) -> tuple[bool, str]:
    """Run endorctl ignore for a single finding UUID.

    Returns a tuple of (success, message).
    """
    user_comment = options.get("comment", "")
    full_comment = f"Triaged via PR comment by {commenter}"
    if user_comment:
        full_comment = f"{user_comment} — {full_comment}"

    cmd = [
        "endorctl", "ignore",
        *_endorctl_auth_flags(),
        f"--namespace={namespace}",
        f"--finding-uuid={uuid}",
        f"--path={IGNORE_FILE}",
        f"--prefix={commenter}",
        f"--reason={reason}",
        f"--username={commenter}@github",
        f"--comments={full_comment}",
    ]

    if "expires" in options:
        cmd.append(f"--expiration-date={options['expires']}")

    if options.get("expire_if_fix"):
        cmd.append("--expire-if-fix-available")

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return True, result.stdout.strip()
    return False, result.stderr.strip()


def commit_ignore_file(commenter: str) -> bool:
    """Stage and commit the updated ignore file to the current branch.

    Returns True if a commit was made, False if there was nothing to commit.
    """
    subprocess.run(["git", "config", "user.name", "github-actions[bot]"], check=True)
    subprocess.run(
        ["git", "config", "user.email", "github-actions[bot]@users.noreply.github.com"],
        check=True,
    )

    status = subprocess.run(
        ["git", "status", "--porcelain", IGNORE_FILE],
        capture_output=True,
        text=True,
    )
    if not status.stdout.strip():
        return False

    subprocess.run(["git", "add", IGNORE_FILE], check=True)
    subprocess.run(
        ["git", "commit", "-m", f"chore: triage findings via PR comment by {commenter}"],
        check=True,
    )
    subprocess.run(["git", "push"], check=True)
    return True


def post_reply(pr_number: str, repo: str, body: str) -> None:
    """Post a reply comment on the pull request via the gh CLI."""
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
            print(f"Error posting reply comment: {result.stderr.strip()}", file=sys.stderr)
    finally:
        os.unlink(tmp_path)


def format_options_summary(options: dict) -> list[str]:
    """Return human-readable lines describing which options were applied."""
    lines = []
    if "comment" in options:
        lines.append(f'  - comment: `"{options["comment"]}"`')
    if "expires" in options:
        lines.append(f'  - expires: `{options["expires"]}`')
    if options.get("expire_if_fix"):
        lines.append("  - will auto-expire when a fix becomes available")
    return lines


def main() -> None:
    """Entry point."""
    namespace = os.environ["ENDOR_NAMESPACE"]
    pr_number = os.environ["PR_NUMBER"]
    repo = os.environ["REPO"]
    comment_body = os.environ["COMMENT_BODY"].strip()
    commenter = os.environ["COMMENTER"]

    command_key, numbers, options = parse_command(comment_body)
    if not command_key:
        print("No valid /endor command found in comment. Nothing to do.")
        return

    reason = COMMAND_MAP[command_key]
    label = COMMAND_LABELS[command_key]

    uuid_map = fetch_uuid_map(pr_number, repo)
    if not uuid_map:
        post_reply(
            pr_number,
            repo,
            "❌ Could not find the findings list. Please re-run the scan to generate a "
            "fresh triage comment, then try again.",
        )
        sys.exit(1)

    # Build the command echo line for the reply
    cmd_display = f"/endor {command_key} {', '.join(numbers)}"
    if "comment" in options:
        cmd_display += f' --comment="{options["comment"]}"'
    if "expires" in options:
        cmd_display += f' --expires={options["expires"]}'
    if options.get("expire_if_fix"):
        cmd_display += " --expire-if-fix"

    result_lines: list[str] = [f"**@{commenter}** ran `{cmd_display}`\n"]

    options_summary = format_options_summary(options)
    if options_summary:
        result_lines.append("Options applied:")
        result_lines.extend(options_summary)
        result_lines.append("")

    any_success = False

    for num in numbers:
        uuid = uuid_map.get(num)
        if not uuid:
            result_lines.append(f"⚠️ Finding **{num}** was not found in the findings list.")
            continue

        success, msg = run_ignore(uuid, namespace, reason, commenter, options)
        if success:
            any_success = True
            result_lines.append(f"✅ Finding **{num}** marked as **{label}**.")
        else:
            result_lines.append(f"❌ Finding **{num}** could not be triaged: `{msg}`")

    if any_success:
        committed = commit_ignore_file(commenter)
        if committed:
            result_lines.append(
                f"\n> `{IGNORE_FILE}` updated and committed to this branch. "
                "Re-run the scan to confirm findings are dismissed."
            )
        else:
            result_lines.append(
                f"\n> No changes were written to `{IGNORE_FILE}` "
                "(entries may already exist)."
            )

    post_reply(pr_number, repo, "\n".join(result_lines))


if __name__ == "__main__":
    main()
