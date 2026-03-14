"""
==============================================================================
DNS Hygiene Checks
==============================================================================
Nameserver responsiveness, SOA serial consistency, and dangling CNAME
detection for subdomain takeover prevention.
"""

import socket

import dns.resolver
import dns.rdatatype
import dns.exception


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
