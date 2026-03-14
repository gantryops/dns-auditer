"""
==============================================================================
TLS & Certificate Checks
==============================================================================
Certificate expiry, protocol version, cipher suite strength, Subject
Alternative Name coverage, Certificate Transparency log verification,
and CAA record validation.

All TLS checks share a single connection via check_tls(), which calls
_connect_tls() once and fans out to the individual check functions.
"""

import datetime
import hashlib
import json
import re
import socket
import ssl
import urllib.request
import urllib.error

import dns.resolver
import dns.exception


# Certificate expiry thresholds
CERT_WARN_DAYS = 30
CERT_FAIL_DAYS = 7

# Cipher suites considered weak or broken.  Any cipher name containing one of
# these substrings is flagged.  Covers RC4, triple-DES, export-grade ciphers,
# null encryption, and anonymous key exchange.
_WEAK_CIPHER_RE = re.compile(r"RC4|3DES|DES-CBC3|EXPORT|NULL|anon", re.IGNORECASE)


# ==============================================================================
# TLS Connection Helper
# ==============================================================================

def _connect_tls(domain: str) -> tuple[dict, bytes, str, tuple]:
    """
    Establish a TLS connection and return all the data needed by the
    individual check functions.

    Returns:
        (cert_dict, cert_der, protocol_version, cipher_info)
        - cert_dict:         parsed certificate from getpeercert()
        - cert_der:          raw DER-encoded certificate bytes
        - protocol_version:  e.g. "TLSv1.3"
        - cipher_info:       (name, protocol, bits) from sock.cipher()
    """
    ctx = ssl.create_default_context()
    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as sock:
        sock.settimeout(10)
        sock.connect((domain, 443))
        cert_dict = sock.getpeercert()
        cert_der = sock.getpeercert(binary_form=True)
        protocol = sock.version()
        cipher = sock.cipher()
    return cert_dict, cert_der, protocol, cipher


# ==============================================================================
# Individual Check Functions
# ==============================================================================

def _check_cert_expiry(cert: dict) -> dict:
    """Check certificate expiry against warning/failure thresholds."""
    not_after = ssl.cert_time_to_seconds(cert["notAfter"])
    expiry_dt = datetime.datetime.fromtimestamp(not_after, tz=datetime.timezone.utc)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    days_left = (expiry_dt - now).days

    issuer = dict(x[0] for x in cert.get("issuer", []))
    issuer_name = issuer.get("organizationName", "unknown")

    if days_left < CERT_FAIL_DAYS:
        status = "fail"
    elif days_left < CERT_WARN_DAYS:
        status = "warn"
    else:
        status = "pass"

    # The message and expires date are stable across days — only the status
    # changes when crossing a threshold, avoiding noisy daily commits.
    return {"tls_cert": {
        "status": status,
        "message": f"Certificate expires {expiry_dt.date()}",
        "expires": str(expiry_dt.date()),
        "issuer": issuer_name,
    }}


def _check_protocol(protocol: str) -> dict:
    """Flag deprecated TLS protocol versions (SSLv3, TLS 1.0, TLS 1.1)."""
    deprecated = {"SSLv3", "TLSv1", "TLSv1.1"}
    if protocol in deprecated:
        return {"tls_protocol": {
            "status": "fail",
            "message": f"Deprecated protocol: {protocol}",
        }}
    return {"tls_protocol": {
        "status": "pass",
        "message": f"Protocol: {protocol}",
    }}


def _check_cipher(cipher_info: tuple) -> dict:
    """Flag weak or broken cipher suites (RC4, 3DES, export, null, anon)."""
    name, _, bits = cipher_info
    if _WEAK_CIPHER_RE.search(name):
        return {"tls_cipher": {
            "status": "warn",
            "message": f"Weak cipher: {name} ({bits} bits)",
        }}
    return {"tls_cipher": {
        "status": "pass",
        "message": f"Cipher: {name} ({bits} bits)",
    }}


def _check_cert_coverage(
    cert: dict,
    domain: str,
    expected_subdomains: list[str] | None = None,
) -> dict:
    """
    Verify the certificate's SANs cover the domain and expected subdomains.

    Checks three things in order of severity:
      1. Does the cert cover the bare domain at all?  (fail if not)
      2. Are any expected_subdomains missing?          (warn if so)
      3. Is www.<domain> covered?                      (warn if not)
    A wildcard (*.domain) satisfies all subdomain checks.
    """
    sans = cert.get("subjectAltName", ())
    dns_names = [name for type_, name in sans if type_ == "DNS"]

    if not dns_names:
        return {"cert_coverage": {
            "status": "fail",
            "message": "Certificate has no Subject Alternative Names",
        }}

    wildcard = f"*.{domain}"
    domain_covered = domain in dns_names or wildcard in dns_names
    www_covered = f"www.{domain}" in dns_names or wildcard in dns_names

    # The cert must cover the bare domain at minimum
    if not domain_covered:
        return {"cert_coverage": {
            "status": "fail",
            "message": f"Certificate does not cover {domain} (SANs: {', '.join(dns_names)})",
            "sans": dns_names,
        }}

    # Check user-specified expected subdomains
    missing = []
    if expected_subdomains:
        for sub in expected_subdomains:
            fqdn = f"{sub}.{domain}"
            if fqdn not in dns_names and wildcard not in dns_names:
                missing.append(fqdn)

    if missing:
        return {"cert_coverage": {
            "status": "warn",
            "message": f"Certificate missing expected subdomains: {', '.join(missing)}",
            "sans": dns_names,
        }}
    elif not www_covered:
        return {"cert_coverage": {
            "status": "warn",
            "message": f"Certificate does not cover www.{domain}",
            "sans": dns_names,
        }}
    elif wildcard in dns_names:
        return {"cert_coverage": {
            "status": "pass",
            "message": f"Wildcard certificate (*.{domain}) — covers all subdomains",
            "sans": dns_names,
        }}
    else:
        return {"cert_coverage": {
            "status": "pass",
            "message": f"Certificate covers {domain} and {len(dns_names)} SAN(s)",
            "sans": dns_names,
        }}


def _check_ct_log(domain: str, cert_der: bytes) -> dict:
    """
    Verify certificates for this domain appear in Certificate Transparency logs.

    Queries crt.sh (a public CT log aggregator) for any logged certificates
    matching the domain.  A domain with no CT entries may indicate certificates
    were issued outside normal CA processes.
    """
    try:
        fingerprint = hashlib.sha256(cert_der).hexdigest()

        url = f"https://crt.sh/?q={domain}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "dns-auditer/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            entries = json.loads(resp.read().decode())

        if not entries:
            return {"ct_log": {
                "status": "fail",
                "message": "No certificates found in Certificate Transparency logs",
                "fingerprint": fingerprint,
            }}

        return {"ct_log": {
            "status": "pass",
            "message": f"Found {len(entries)} CT log entry/entries for this domain",
            "fingerprint": fingerprint,
        }}
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as e:
        return {"ct_log": {
            "status": "warn",
            "message": f"Could not query Certificate Transparency logs: {e}",
        }}


def _check_caa(domain: str) -> dict:
    """Check for CAA records that restrict which CAs can issue certificates."""
    try:
        answers = dns.resolver.resolve(domain, "CAA")
        records = [r.to_text() for r in answers]
        return {"caa": {
            "status": "pass",
            "message": f"CAA records: {'; '.join(records)}",
        }}
    except dns.resolver.NoAnswer:
        return {"caa": {
            "status": "warn",
            "message": "No CAA records — any CA can issue certificates for this domain",
        }}
    except dns.resolver.NXDOMAIN:
        return {"caa": {"status": "fail", "message": "Domain does not exist"}}
    except dns.exception.DNSException as e:
        return {"caa": {"status": "warn", "message": f"CAA lookup failed: {e}"}}


# ==============================================================================
# Public API
# ==============================================================================

def check_tls(
    domain: str,
    expected_subdomains: list[str] | None = None,
) -> dict:
    """
    Run all TLS-related checks against a domain.

    Establishes a single TLS connection and runs certificate expiry,
    protocol version, cipher strength, and SAN coverage checks.  Also
    queries Certificate Transparency logs (via crt.sh) and DNS CAA records.
    """
    checks = {}

    try:
        cert, cert_der, protocol, cipher = _connect_tls(domain)

        # Certificate expiry
        checks.update(_check_cert_expiry(cert))

        # Protocol version — SSLv3, TLS 1.0, TLS 1.1 are deprecated
        checks.update(_check_protocol(protocol))

        # Cipher suite strength
        checks.update(_check_cipher(cipher))

        # Subject Alternative Name coverage
        checks.update(_check_cert_coverage(cert, domain, expected_subdomains))

        # Certificate Transparency — separate HTTP request to crt.sh
        checks.update(_check_ct_log(domain, cert_der))

    except ssl.SSLCertVerificationError as e:
        checks["tls_cert"] = {
            "status": "fail",
            "message": f"Certificate verification failed: {e}",
        }
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
        checks["tls_cert"] = {
            "status": "fail",
            "message": f"Could not connect on port 443: {e}",
        }

    # CAA records — independent DNS query, runs even if TLS connection failed
    checks.update(_check_caa(domain))

    return checks
