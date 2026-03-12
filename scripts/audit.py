#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "checkdmarc",
#     "pyyaml",
# ]
# ///
"""
==============================================================================
DNS Security Audit Script
==============================================================================
Reads domains.yml, runs checkdmarc against each domain, and writes
structured JSON results to results/<domain>.json.

The results are designed to be diffed against previous runs by
manage_issues.py to detect changes and regressions.
"""

import json
import subprocess
import sys
from pathlib import Path

import yaml

DOMAINS_FILE = Path("domains.yml")
RESULTS_DIR = Path("results")


def load_domains() -> list[str]:
    """Load domain list from domains.yml."""
    with open(DOMAINS_FILE) as f:
        config = yaml.safe_load(f)
    return config.get("domains", [])


def run_checkdmarc(domain: str) -> dict:
    """
    Run checkdmarc for a single domain and return parsed JSON.

    We shell out rather than importing as a library so the workflow
    stays simple and version-independent.
    """
    cmd = ["checkdmarc", domain, "-f", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {
            "error": f"checkdmarc failed: {result.stderr.strip()}",
            "domain": domain,
        }


def extract_findings(domain: str, raw: dict) -> dict:
    """
    Normalise checkdmarc output into a consistent findings structure.

    Each finding has a status (pass/warn/fail) and a human-readable
    message. This normalised format is what manage_issues.py diffs.
    """
    findings = {
        "domain": domain,
        "checks": {},
    }

    # ------------------------------------------------------------------ SPF
    spf = raw.get("spf", {})
    if "error" in spf:
        findings["checks"]["spf"] = {
            "status": "fail",
            "message": spf["error"],
        }
    elif spf.get("valid", False):
        warnings = spf.get("warnings", [])
        findings["checks"]["spf"] = {
            "status": "warn" if warnings else "pass",
            "message": "; ".join(warnings) if warnings else "Valid SPF record",
            "record": spf.get("record", ""),
        }
    else:
        findings["checks"]["spf"] = {
            "status": "fail",
            "message": "No valid SPF record found",
        }

    # --------------------------------------------------------------- DMARC
    dmarc = raw.get("dmarc", {})
    if "error" in dmarc:
        findings["checks"]["dmarc"] = {
            "status": "fail",
            "message": dmarc["error"],
        }
    elif dmarc.get("valid", False):
        warnings = dmarc.get("warnings", [])
        record = dmarc.get("record", "")
        policy = dmarc.get("tags", {}).get("p", {}).get("value", "none")

        if policy == "none" and not warnings:
            warnings = ["DMARC policy is 'none' — no enforcement"]

        findings["checks"]["dmarc"] = {
            "status": "warn" if warnings else "pass",
            "message": "; ".join(warnings) if warnings else f"Valid DMARC (p={policy})",
            "record": record,
            "policy": policy,
        }
    else:
        findings["checks"]["dmarc"] = {
            "status": "fail",
            "message": "No valid DMARC record found",
        }

    # -------------------------------------------------------------- DNSSEC
    dnssec = raw.get("dnssec", False)
    findings["checks"]["dnssec"] = {
        "status": "pass" if dnssec else "warn",
        "message": "DNSSEC enabled" if dnssec else "DNSSEC not enabled",
    }

    # --------------------------------------------------------- Nameservers
    ns = raw.get("ns", {})
    hostnames = ns.get("hostnames", [])
    if hostnames:
        findings["checks"]["nameservers"] = {
            "status": "pass",
            "message": f"Nameservers: {', '.join(hostnames)}",
        }

    # ------------------------------------------------------------------ MX
    mx = raw.get("mx", {})
    if "error" in mx:
        findings["checks"]["mx"] = {
            "status": "fail",
            "message": mx["error"],
        }
    elif mx.get("hosts"):
        hosts = [h.get("hostname", "unknown") for h in mx["hosts"]]
        findings["checks"]["mx"] = {
            "status": "pass",
            "message": f"MX records: {', '.join(hosts)}",
        }
    else:
        findings["checks"]["mx"] = {
            "status": "warn",
            "message": "No MX records found",
        }

    return findings


def main():
    domains = load_domains()
    if not domains:
        print("No domains configured in domains.yml", file=sys.stderr)
        sys.exit(1)

    RESULTS_DIR.mkdir(exist_ok=True)

    all_passed = True
    for domain in domains:
        print(f"Auditing {domain}...")
        raw = run_checkdmarc(domain)

        if "error" in raw:
            print(f"  ERROR: {raw['error']}", file=sys.stderr)
            findings = {
                "domain": domain,
                "checks": {
                    "error": {"status": "fail", "message": raw["error"]}
                },
            }
            all_passed = False
        else:
            findings = extract_findings(domain, raw)
            for check_name, check in findings["checks"].items():
                status = check["status"]
                icon = {"pass": "✓", "warn": "⚠", "fail": "✗"}.get(status, "?")
                print(f"  {icon} {check_name}: {check['message']}")
                if status == "fail":
                    all_passed = False

        result_file = RESULTS_DIR / f"{domain}.json"
        with open(result_file, "w") as f:
            json.dump(findings, f, indent=2)

    if not all_passed:
        print("\nSome checks failed — see results/ for details.")


if __name__ == "__main__":
    main()
