"""Naming and normalization rules for SRX objects.

Rules:
  - IP/CIDR without prefix becomes /32
  - IP/CIDR with host bits set is normalized to its network address
  - Single port becomes "poac-{proto}-{port}"
  - Port range becomes "poac-{proto}-{start}-to-{end}"
"""
from __future__ import annotations

import ipaddress
import re

POLICY_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,62}$")
ZONE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9_\-<>.]{1,63}$")


def normalize_cidr(s: str) -> str:
    """Normalize an IP/CIDR string.

    >>> normalize_cidr("10.20.0.5")
    '10.20.0.5/32'
    >>> normalize_cidr("10.20.0.5/24")
    '10.20.0.0/24'
    >>> normalize_cidr("10.20.0.0/24")
    '10.20.0.0/24'
    >>> normalize_cidr("2001:db8::1/64")
    '2001:db8::/64'
    """
    s = s.strip()
    if not s:
        raise ValueError("empty CIDR")
    if "/" not in s:
        addr = ipaddress.ip_address(s)
        return f"{addr}/{addr.max_prefixlen}"
    net = ipaddress.ip_network(s, strict=False)
    return str(net)


def cidr_was_normalized(original: str) -> bool:
    """Return True if the original string was not in canonical form."""
    original = original.strip()
    try:
        return normalize_cidr(original) != original
    except ValueError:
        return False


def ip_to_object_name(prefix: str, cidr: str) -> str:
    """Use the normalized CIDR itself as the object name.

    >>> ip_to_object_name("src", "10.20.0.0/24")
    '10.20.0.0/24'
    >>> ip_to_object_name("dst", "203.0.113.5")
    '203.0.113.5/32'
    """
    return normalize_cidr(cidr)


def parse_port_spec(s: str) -> tuple[str, str]:
    """Parse a port spec: '443' or '8000-8100'.

    Returns (port_spec_for_srx, kind) where kind is 'single' or 'range'.
    """
    s = s.strip()
    if not s:
        raise ValueError("empty port spec")
    if "-" in s:
        parts = s.split("-")
        if len(parts) != 2:
            raise ValueError(f"invalid range '{s}': expected 'start-end'")
        start_s, end_s = parts
        try:
            start_i = int(start_s)
            end_i = int(end_s)
        except ValueError as e:
            raise ValueError(f"non-integer port in '{s}': {e}") from e
        if not (1 <= start_i <= 65535):
            raise ValueError(f"port out of range: {start_i}")
        if not (1 <= end_i <= 65535):
            raise ValueError(f"port out of range: {end_i}")
        if start_i >= end_i:
            raise ValueError(f"range start must be < end: {s}")
        return f"{start_i}-{end_i}", "range"
    try:
        port = int(s)
    except ValueError as e:
        raise ValueError(f"non-integer port: '{s}'") from e
    if not (1 <= port <= 65535):
        raise ValueError(f"port out of range: {port}")
    return str(port), "single"


def port_to_app_name(protocol: str, port_spec: str) -> str:
    """Build application object name as '{protocol}-{port}'.

    >>> port_to_app_name("tcp", "443")
    'tcp-443'
    >>> port_to_app_name("tcp", "8000-8100")
    'tcp-8000-to-8100'
    >>> port_to_app_name("udp", "53")
    'udp-53'
    """
    if "-" in port_spec:
        start, end = port_spec.split("-", 1)
        return f"{protocol}-{start}-to-{end}"
    return f"{protocol}-{port_spec}"
