#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "checkdmarc",
#     "dnspython",
#     "pyyaml",
# ]
# ///
"""
==============================================================================
DNS Security Audit Script
==============================================================================
Runs a comprehensive set of DNS, email, TLS, and web security checks
against every domain in domains.yml. Writes structured JSON results
to results/<domain>.json for diffing and issue management.

Check categories:
  - Email: SPF, DMARC, DNSSEC, MX (via checkdmarc)
  - TLS: certificate expiry, protocol version, cipher suite, SAN coverage,
         Certificate Transparency, CAA records
  - Web: HTTPS redirect, HSTS, security headers
  - DNS: NS health, dangling CNAMEs, SOA consistency

Per-domain configuration (skip_checks, severity_overrides) is supported
via extended domains.yml format.  See domains.yml for examples.
"""

import json
import sys
from pathlib import Path

from checks.email import check_email
from checks.tls import check_tls
from checks.web import check_web
from checks.dns import check_dns
from config import load_domains


RESULTS_DIR = Path("results")


# ==============================================================================
# Display Helpers
# ==============================================================================

STATUS_ICONS = {"pass": "✓", "warn": "⚠", "fail": "✗", "skipped": "—"}


def print_checks(checks: dict):
    """Print check results with status icons."""
    for check_name, check in checks.items():
        icon = STATUS_ICONS.get(check["status"], "?")
        print(f"    {icon} {check_name}: {check['message']}")


# ==============================================================================
# Per-Domain Configuration
# ==============================================================================

def apply_overrides(checks: dict, skip_checks: list[str], severity_overrides: dict) -> dict:
    """
    Apply per-domain configuration to check results.

    Skipped checks are marked with status "skipped" so manage_issues.py
    can close any existing issues.  Severity overrides replace the check's
    status while preserving the original in an "original_status" field
    for auditability.
    """
    for name in skip_checks:
        checks[name] = {"status": "skipped", "message": "Check skipped by configuration"}

    for name, new_status in severity_overrides.items():
        if name in checks and checks[name]["status"] != "skipped":
            checks[name]["original_status"] = checks[name]["status"]
            checks[name]["status"] = new_status

    return checks


# ==============================================================================
# Main
# ==============================================================================

def main():
    domains = load_domains()
    if not domains:
        print("No domains configured in domains.yml", file=sys.stderr)
        sys.exit(1)

    RESULTS_DIR.mkdir(exist_ok=True)

    all_passed = True
    for domain, config in domains:
        print(f"\n{'='*60}")
        print(f"  Auditing {domain}")
        print(f"{'='*60}")

        skip_checks = config.get("skip_checks", [])
        severity_overrides = config.get("severity_overrides", {})
        expected_subdomains = config.get("expected_subdomains")

        findings = {"domain": domain, "checks": {}}

        # Email checks
        print("\n  Email:")
        email_checks = check_email(domain)
        findings["checks"].update(email_checks)
        print_checks(email_checks)

        # TLS checks (certificate, protocol, cipher, coverage, CT, CAA)
        print("\n  TLS:")
        tls_checks = check_tls(domain, expected_subdomains=expected_subdomains)
        findings["checks"].update(tls_checks)
        print_checks(tls_checks)

        # Web security checks
        print("\n  Web:")
        web_checks = check_web(domain)
        findings["checks"].update(web_checks)
        print_checks(web_checks)

        # DNS hygiene checks
        print("\n  DNS:")
        dns_checks = check_dns(domain)
        findings["checks"].update(dns_checks)
        print_checks(dns_checks)

        # Apply per-domain overrides (skip checks, override severities)
        if skip_checks or severity_overrides:
            print("\n  Overrides:")
            findings["checks"] = apply_overrides(
                findings["checks"], skip_checks, severity_overrides,
            )
            for name in [*skip_checks, *severity_overrides]:
                if name in findings["checks"]:
                    check = findings["checks"][name]
                    original = check.get("original_status")
                    if check["status"] == "skipped":
                        print(f"    — {name}: skipped by configuration")
                    elif original:
                        print(f"    ↻ {name}: {original} → {check['status']} (overridden)")

        # Track failures
        for check in findings["checks"].values():
            if check["status"] == "fail":
                all_passed = False

        # Write results
        result_file = RESULTS_DIR / f"{domain}.json"
        with open(result_file, "w") as f:
            json.dump(findings, f, indent=2)

    if not all_passed:
        print(f"\n{'='*60}")
        print("  Some checks failed — see results/ for details.")
        print(f"{'='*60}")


if __name__ == "__main__":
    main()
