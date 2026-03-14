"""
==============================================================================
Email Security Checks
==============================================================================
SPF, DMARC, DNSSEC, and MX checks via the checkdmarc library.
"""

import json
import subprocess


def _run_checkdmarc(domain: str) -> dict:
    """Shell out to checkdmarc and return parsed JSON."""
    cmd = ["checkdmarc", domain, "-f", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": f"checkdmarc failed: {result.stderr.strip()}"}


def check_email(domain: str) -> dict:
    """Run all email-related checks and return findings."""
    raw = _run_checkdmarc(domain)
    if "error" in raw:
        return {"checkdmarc_error": {"status": "fail", "message": raw["error"]}}

    checks = {}

    # ------------------------------------------------------------ SPF
    spf = raw.get("spf", {})
    if "error" in spf:
        checks["spf"] = {"status": "fail", "message": spf["error"]}
    elif spf.get("valid", False):
        warnings = spf.get("warnings", [])
        checks["spf"] = {
            "status": "warn" if warnings else "pass",
            "message": "; ".join(warnings) if warnings else "Valid SPF record",
            "record": spf.get("record", ""),
        }
    else:
        checks["spf"] = {"status": "fail", "message": "No valid SPF record found"}

    # ---------------------------------------------------------- DMARC
    dmarc = raw.get("dmarc", {})
    if "error" in dmarc:
        checks["dmarc"] = {"status": "fail", "message": dmarc["error"]}
    elif dmarc.get("valid", False):
        warnings = dmarc.get("warnings", [])
        policy = dmarc.get("tags", {}).get("p", {}).get("value", "none")
        if policy == "none" and not warnings:
            warnings = ["DMARC policy is 'none' — no enforcement"]
        checks["dmarc"] = {
            "status": "warn" if warnings else "pass",
            "message": "; ".join(warnings) if warnings else f"Valid DMARC (p={policy})",
            "record": dmarc.get("record", ""),
            "policy": policy,
        }
    else:
        checks["dmarc"] = {"status": "fail", "message": "No valid DMARC record found"}

    # --------------------------------------------------------- DNSSEC
    dnssec = raw.get("dnssec", False)
    checks["dnssec"] = {
        "status": "pass" if dnssec else "warn",
        "message": "DNSSEC enabled" if dnssec else "DNSSEC not enabled",
    }

    # ------------------------------------------------------------- MX
    mx = raw.get("mx", {})
    if "error" in mx:
        checks["mx"] = {"status": "fail", "message": mx["error"]}
    elif mx.get("hosts"):
        hosts = [h.get("hostname", "unknown") for h in mx["hosts"]]
        checks["mx"] = {"status": "pass", "message": f"MX records: {', '.join(hosts)}"}
    else:
        checks["mx"] = {"status": "warn", "message": "No MX records found"}

    return checks
