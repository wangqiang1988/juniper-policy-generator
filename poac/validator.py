"""Validation helpers."""
from __future__ import annotations

from .naming import (
    POLICY_NAME_PATTERN,
    ZONE_NAME_PATTERN,
    normalize_cidr,
    parse_port_spec,
)


class ValidationError(Exception):
    """Raised when user input fails validation."""


def validate_policy_name(name: str) -> None:
    name = name.strip()
    if not POLICY_NAME_PATTERN.match(name):
        raise ValidationError(
            f"invalid policy name '{name}': must start with a-z/0-9, "
            f"contain only [a-z0-9_-], max 63 chars"
        )


def validate_zone(zone: str, field: str) -> None:
    zone = zone.strip()
    if not zone:
        raise ValidationError(f"{field} is required")
    if not ZONE_NAME_PATTERN.match(zone):
        raise ValidationError(
            f"invalid {field} '{zone}': must match [a-zA-Z0-9_-<>.]{{1,63}}"
        )


def normalize_ip_list(raw: list[str]) -> list[str]:
    """Normalize a list of IP/CIDR strings, preserving order, dropping blanks."""
    out: list[str] = []
    for s in raw:
        s = s.strip()
        if not s:
            continue
        try:
            out.append(normalize_cidr(s))
        except ValueError as e:
            raise ValidationError(f"invalid IP/CIDR '{s}': {e}") from e
    return out


def normalize_port_list(raw: list[str]) -> list[tuple[str, str]]:
    """Return list of (port_spec, kind) for non-empty entries."""
    out: list[tuple[str, str]] = []
    for s in raw:
        s = s.strip()
        if not s:
            continue
        try:
            out.append(parse_port_spec(s))
        except ValueError as e:
            raise ValidationError(f"invalid port '{s}': {e}") from e
    return out


def validate_input_has_content(
    src_ips: list[str],
    dst_ips: list[str],
    tcp_ports: list[str],
    udp_ports: list[str],
) -> None:
    if not (src_ips or dst_ips or tcp_ports or udp_ports):
        raise ValidationError(
            "at least one source IP, destination IP, TCP port, or UDP port is required"
        )
