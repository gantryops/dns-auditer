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
  - TLS: certificate expiry, chain validity, CAA records
  - Web: HTTPS redirect, HSTS, security headers
  - DNS: NS health, dangling CNAMEs, SOA consistency
"""

import datetime
import json
import socket
import ssl
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

import dns.resolver
import dns.rdatatype
import dns.exception
import yaml


DOMAINS_FILE = Path("domains.yml")
RESULTS_DIR = Path("results")

# Certificate expiry thresholds
CERT_WARN_DAYS = 30
CERT_FAIL_DAYS = 7


# ==============================================================================
# Email Checks (via checkdmarc)
# ==============================================================================

def run_checkdmarc(domain: str) -> dict:
    """Shell out to checkdmarc and return parsed JSON."""
    cmd = ["checkdmarc", domain, "-f", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return {"error": f"checkdmarc failed: {result.stderr.strip()}"}


def check_email(domain: str, raw: dict) -> dict:
    """Extract email-related findings from checkdmarc output."""
    checks = {}

    # SPF
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

    # DMARC
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

    # DNSSEC
    dnssec = raw.get("dnssec", False)
    checks["dnssec"] = {
        "status": "pass" if dnssec else "warn",
        "message": "DNSSEC enabled" if dnssec else "DNSSEC not enabled",
    }

    # MX
    mx = raw.get("mx", {})
    if "error" in mx:
        checks["mx"] = {"status": "fail", "message": mx["error"]}
    elif mx.get("hosts"):
        hosts = [h.get("hostname", "unknown") for h in mx["hosts"]]
        checks["mx"] = {"status": "pass", "message": f"MX records: {', '.join(hosts)}"}
    else:
        checks["mx"] = {"status": "warn", "message": "No MX records found"}

    return checks


# ==============================================================================
# TLS Checks
# ==============================================================================

def check_tls(domain: str) -> dict:
    """Check TLS certificate validity, expiry, and CAA records."""
    checks = {}

    # -------------------------------------------------------- Certificate
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
            sock.settimeout(10)
            sock.connect((domain, 443))
            cert = sock.getpeercert()

        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
        expiry_dt = datetime.datetime.fromtimestamp(not_after, tz=datetime.timezone.utc)
        now = datetime.datetime.now(tz=datetime.timezone.utc)
        days_left = (expiry_dt - now).days

        if days_left < CERT_FAIL_DAYS:
            checks["tls_cert"] = {
                "status": "fail",
                "message": f"Certificate expires in {days_left} days ({expiry_dt.date()})",
                "days_left": days_left,
            }
        elif days_left < CERT_WARN_DAYS:
            checks["tls_cert"] = {
                "status": "warn",
                "message": f"Certificate expires in {days_left} days ({expiry_dt.date()})",
                "days_left": days_left,
            }
        else:
            checks["tls_cert"] = {
                "status": "pass",
                "message": f"Certificate valid for {days_left} days (expires {expiry_dt.date()})",
                "days_left": days_left,
            }

        issuer = dict(x[0] for x in cert.get("issuer", []))
        checks["tls_cert"]["issuer"] = issuer.get("organizationName", "unknown")

    except ssl.SSLCertVerificationError as e:
        checks["tls_cert"] = {"status": "fail", "message": f"Certificate verification failed: {e}"}
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        checks["tls_cert"] = {"status": "fail", "message": f"Could not connect on port 443: {e}"}

    # ------------------------------------------------------------- CAA
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        records = [r.to_text() for r in answers]
        checks["caa"] = {
            "status": "pass",
            "message": f"CAA records: {'; '.join(records)}",
        }
    except dns.resolver.NoAnswer:
        checks["caa"] = {
            "status": "warn",
            "message": "No CAA records — any CA can issue certificates for this domain",
        }
    except dns.resolver.NXDOMAIN:
        checks["caa"] = {"status": "fail", "message": "Domain does not exist"}
    except dns.exception.DNSException as e:
        checks["caa"] = {"status": "warn", "message": f"CAA lookup failed: {e}"}

    return checks


# ==============================================================================
# Web Security Checks
# ==============================================================================

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Handler that captures redirects instead of following them."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

    def http_error_301(self, req, fp, code, msg, headers):
        return fp

    http_error_302 = http_error_301
    http_error_303 = http_error_301
    http_error_307 = http_error_301
    http_error_308 = http_error_301


def check_web(domain: str) -> dict:
    """Check HTTPS redirect, HSTS, and security headers."""
    checks = {}

    # -------------------------------------------------- HTTPS redirect
    try:
        req = urllib.request.Request(
            f"http://{domain}/",
            method="HEAD",
            headers={"User-Agent": "dns-auditer/1.0"},
        )
        opener = urllib.request.build_opener(NoRedirectHandler)
        resp = opener.open(req, timeout=10)
        location = resp.headers.get("Location", "")

        if resp.status in (301, 302, 307, 308) and location.startswith("https://"):
            checks["https_redirect"] = {
                "status": "pass",
                "message": f"HTTP redirects to HTTPS ({resp.status} → {location})",
            }
        elif resp.status in (301, 302, 307, 308):
            checks["https_redirect"] = {
                "status": "warn",
                "message": f"HTTP redirects but not to HTTPS ({resp.status} → {location})",
            }
        else:
            checks["https_redirect"] = {
                "status": "fail",
                "message": f"HTTP does not redirect to HTTPS (status {resp.status})",
            }
    except Exception as e:
        checks["https_redirect"] = {
            "status": "warn",
            "message": f"Could not check HTTP redirect: {e}",
        }

    # ---------------------------------------- HTTPS headers
    try:
        req = urllib.request.Request(
            f"https://{domain}/",
            method="HEAD",
            headers={"User-Agent": "dns-auditer/1.0"},
        )
        resp = urllib.request.urlopen(req, timeout=10)
        headers = resp.headers

        # HSTS
        hsts = headers.get("Strict-Transport-Security")
        if hsts:
            checks["hsts"] = {"status": "pass", "message": f"HSTS: {hsts}"}
        else:
            checks["hsts"] = {"status": "warn", "message": "No HSTS header"}

        # Content-Security-Policy
        csp = headers.get("Content-Security-Policy")
        if csp:
            display = csp[:120] + "..." if len(csp) > 120 else csp
            checks["csp"] = {"status": "pass", "message": f"CSP: {display}"}
        else:
            checks["csp"] = {"status": "warn", "message": "No Content-Security-Policy header"}

        # X-Frame-Options
        xfo = headers.get("X-Frame-Options")
        if xfo:
            checks["x_frame_options"] = {"status": "pass", "message": f"X-Frame-Options: {xfo}"}
        else:
            checks["x_frame_options"] = {
                "status": "warn",
                "message": "No X-Frame-Options header (CSP frame-ancestors is the modern replacement)",
            }

        # X-Content-Type-Options
        xcto = headers.get("X-Content-Type-Options")
        if xcto:
            checks["x_content_type_options"] = {"status": "pass", "message": f"X-Content-Type-Options: {xcto}"}
        else:
            checks["x_content_type_options"] = {"status": "warn", "message": "No X-Content-Type-Options header"}

        # Permissions-Policy
        pp = headers.get("Permissions-Policy")
        if pp:
            display = pp[:120] + "..." if len(pp) > 120 else pp
            checks["permissions_policy"] = {"status": "pass", "message": f"Permissions-Policy: {display}"}
        else:
            checks["permissions_policy"] = {"status": "warn", "message": "No Permissions-Policy header"}

    except Exception as e:
        checks["https_headers"] = {
            "status": "fail",
            "message": f"Could not fetch HTTPS headers: {e}",
        }

    return checks


# ==============================================================================
# DNS Hygiene Checks
# ==============================================================================

def check_dns(domain: str) -> dict:
    """Check NS health, SOA consistency, and dangling CNAMEs."""
    checks = {}

    # ------------------------------------------- Nameserver responsiveness
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        ns_hosts = [str(r.target).rstrip(".") for r in ns_answers]

        responsive = []
        unresponsive = []
        for ns in ns_hosts:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(ns)]
                resolver.lifetime = 5
                resolver.resolve(domain, "SOA")
                responsive.append(ns)
            except Exception:
                unresponsive.append(ns)

        if unresponsive:
            checks["ns_health"] = {
                "status": "warn",
                "message": f"Unresponsive nameservers: {', '.join(unresponsive)}",
            }
        else:
            checks["ns_health"] = {
                "status": "pass",
                "message": f"All {len(responsive)} nameservers responding",
            }
    except dns.exception.DNSException as e:
        checks["ns_health"] = {"status": "fail", "message": f"NS lookup failed: {e}"}

    # ------------------------------------------------- SOA serial consistency
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        ns_hosts = [str(r.target).rstrip(".") for r in ns_answers]
        serials = {}

        for ns in ns_hosts:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(ns)]
                resolver.lifetime = 5
                soa = resolver.resolve(domain, "SOA")
                serials[ns] = soa[0].serial
            except Exception:
                pass

        unique_serials = set(serials.values())
        if len(unique_serials) > 1:
            checks["soa_consistency"] = {
                "status": "warn",
                "message": f"SOA serials differ across nameservers: {serials}",
            }
        elif len(unique_serials) == 1:
            checks["soa_consistency"] = {
                "status": "pass",
                "message": f"SOA serial consistent: {unique_serials.pop()}",
            }
    except dns.exception.DNSException:
        pass

    # ----------------------------------------------- Dangling CNAME check
    www = f"www.{domain}"
    try:
        cname_answers = dns.resolver.resolve(www, "CNAME")
        target = str(cname_answers[0].target).rstrip(".")
        try:
            dns.resolver.resolve(target, "A")
            checks["dangling_cname"] = {
                "status": "pass",
                "message": f"www CNAME → {target} (resolves)",
            }
        except dns.resolver.NXDOMAIN:
            checks["dangling_cname"] = {
                "status": "fail",
                "message": f"www CNAME → {target} (NXDOMAIN — subdomain takeover risk)",
            }
        except dns.exception.DNSException:
            checks["dangling_cname"] = {
                "status": "warn",
                "message": f"www CNAME → {target} (could not verify resolution)",
            }
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        pass

    return checks


# ==============================================================================
# Main
# ==============================================================================

def load_domains() -> list[str]:
    """Load domain list from domains.yml."""
    with open(DOMAINS_FILE) as f:
        config = yaml.safe_load(f)
    return config.get("domains", [])


def print_checks(checks: dict):
    """Print check results with status icons."""
    for check_name, check in checks.items():
        status = check["status"]
        icon = {"pass": "✓", "warn": "⚠", "fail": "✗"}.get(status, "?")
        print(f"    {icon} {check_name}: {check['message']}")


def main():
    domains = load_domains()
    if not domains:
        print("No domains configured in domains.yml", file=sys.stderr)
        sys.exit(1)

    RESULTS_DIR.mkdir(exist_ok=True)

    all_passed = True
    for domain in domains:
        print(f"\n{'='*60}")
        print(f"  Auditing {domain}")
        print(f"{'='*60}")

        findings = {"domain": domain, "checks": {}}

        # Email checks
        print("\n  Email:")
        raw = run_checkdmarc(domain)
        if "error" in raw:
            email_checks = {"checkdmarc_error": {"status": "fail", "message": raw["error"]}}
        else:
            email_checks = check_email(domain, raw)
        findings["checks"].update(email_checks)
        print_checks(email_checks)

        # TLS checks
        print("\n  TLS:")
        tls_checks = check_tls(domain)
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
