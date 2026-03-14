"""
==============================================================================
Web Security Checks
==============================================================================
HTTPS redirect, HSTS, and common security headers (CSP, X-Frame-Options,
X-Content-Type-Options, Permissions-Policy).
"""

import urllib.request
import urllib.error


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
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
        opener = urllib.request.build_opener(_NoRedirectHandler)
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
