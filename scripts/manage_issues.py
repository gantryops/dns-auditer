#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pyyaml",
# ]
# ///
"""
==============================================================================
Issue Manager for DNS Audit Results
==============================================================================
Reads the current results from results/<domain>.json, compares against
previous results (via git diff), and opens/closes GitHub Issues using
the gh CLI.

Issue lifecycle:
  - A new "fail" or "warn" finding → open an issue
  - A previously failing check now passes → close the issue
  - An existing issue with the same finding → leave it open (no duplicates)

Issues are identified by a label + title convention so we can find and
update them reliably.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

RESULTS_DIR = Path("results")
LABEL = "dns-audit"


def gh(*args: str) -> subprocess.CompletedProcess:
    """Run a gh CLI command and return the result."""
    return subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
    )


def ensure_label_exists():
    """Create the dns-audit label if it doesn't exist."""
    result = gh("label", "list", "--search", LABEL, "--json", "name")
    try:
        labels = json.loads(result.stdout)
        if not any(l["name"] == LABEL for l in labels):
            gh("label", "create", LABEL,
               "--description", "Automated DNS security audit finding",
               "--color", "d93f0b")
    except (json.JSONDecodeError, KeyError):
        gh("label", "create", LABEL,
           "--description", "Automated DNS security audit finding",
           "--color", "d93f0b")


def get_open_issues() -> list[dict]:
    """Get all open issues with the dns-audit label."""
    result = gh("issue", "list",
                "--label", LABEL,
                "--state", "open",
                "--json", "number,title",
                "--limit", "100")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def issue_title(domain: str, check: str) -> str:
    """Generate a deterministic issue title for a finding."""
    return f"[{domain}] {check.upper()} check failed"


def open_issue(domain: str, check: str, finding: dict):
    """Open a new GitHub Issue for a failing check."""
    title = issue_title(domain, check)

    status_icon = {"fail": "🔴", "warn": "🟡"}.get(finding["status"], "⚪")
    body = f"""## {status_icon} {check.upper()} — {finding['status'].upper()}

**Domain:** `{domain}`
**Check:** {check}
**Status:** {finding['status']}
**Details:** {finding['message']}
"""
    if "record" in finding:
        body += f"\n**Current record:**\n```\n{finding['record']}\n```\n"

    body += """
---
*This issue was opened automatically by [dns-auditer](https://github.com/gantryops/dns-auditer). \
It will be closed automatically when the check passes.*
"""

    gh("issue", "create",
       "--title", title,
       "--body", body,
       "--label", LABEL)
    print(f"  Opened: {title}")


def close_issue(issue_number: int, title: str):
    """Close an issue that is now passing."""
    gh("issue", "close", str(issue_number),
       "--comment", "This check is now passing. Closing automatically.")
    print(f"  Closed #{issue_number}: {title}")


def main():
    if not RESULTS_DIR.exists():
        print("No results directory found. Run audit.py first.", file=sys.stderr)
        sys.exit(1)

    ensure_label_exists()
    open_issues = get_open_issues()

    # Build a map of open issue titles → issue numbers
    issue_map = {i["title"]: i["number"] for i in open_issues}

    # Track which issues should remain open
    should_be_open: set[str] = set()

    # Process each domain's results
    for result_file in RESULTS_DIR.glob("*.json"):
        with open(result_file) as f:
            findings = json.load(f)

        domain = findings["domain"]
        print(f"Managing issues for {domain}...")

        for check, finding in findings["checks"].items():
            title = issue_title(domain, check)

            if finding["status"] in ("fail", "warn"):
                should_be_open.add(title)

                if title not in issue_map:
                    # New finding — open an issue
                    open_issue(domain, check, finding)
                else:
                    print(f"  Exists: {title}")
            # "pass" status: we don't add to should_be_open,
            # so it will be closed below if an issue exists

    # Close issues for checks that are now passing
    for title, number in issue_map.items():
        if title not in should_be_open:
            close_issue(number, title)


if __name__ == "__main__":
    main()
