"""
==============================================================================
Domain Configuration Loader
==============================================================================
Parses domains.yml, supporting both simple domain strings and extended
per-domain configuration (skip_checks, severity_overrides,
expected_subdomains).
"""

from pathlib import Path

import yaml

DOMAINS_FILE = Path("domains.yml")


def load_domains(path: Path = DOMAINS_FILE) -> list[tuple[str, dict]]:
    """
    Load domain list from domains.yml.

    Returns a list of (domain_name, config) tuples.  Simple string entries
    get an empty config dict; dict entries are parsed for per-domain settings.

    Supported config keys:
        skip_checks:          list[str]  -- check names to skip entirely
        severity_overrides:   dict       -- {check_name: "pass"|"warn"|"fail"}
        expected_subdomains:  list[str]  -- subdomains the TLS cert should cover
    """
    with open(path) as f:
        raw = yaml.safe_load(f)

    result = []
    for entry in raw.get("domains", []):
        if isinstance(entry, str):
            # Simple format: just a domain name
            result.append((entry, {}))
        elif isinstance(entry, dict):
            # Extended format: {domain_name: {config...}}
            for domain, config in entry.items():
                result.append((domain, config or {}))

    return result
