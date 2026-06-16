"""Render PolicyInput to a complete set of SRX `set` commands.

Order of commands in the output:
  1) Address objects (security address-book global address)
  2) Application objects (security applications application)
  3) Policy with match clauses and action
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Tuple

from jinja2 import Environment, FileSystemLoader

from .models import (
    AddressObject,
    ApplicationObject,
    GeneratedPolicy,
    PolicyInput,
)
from .naming import ip_to_object_name, port_to_app_name
from .validator import (
    normalize_ip_list,
    normalize_port_list,
    validate_input_has_content,
    validate_policy_name,
    validate_zone,
    ValidationError,
)


def _build_objects(
    policy_input: PolicyInput,
) -> tuple[list[AddressObject], list[ApplicationObject], GeneratedPolicy]:
    src_normalized = normalize_ip_list(policy_input.src_ips)
    dst_normalized = normalize_ip_list(policy_input.dst_ips)
    tcp_normalized = normalize_port_list(policy_input.tcp_ports)
    udp_normalized = normalize_port_list(policy_input.udp_ports)

    validate_input_has_content(src_normalized, dst_normalized, tcp_normalized, udp_normalized)

    addresses: list[AddressObject] = []
    src_names: list[str] = []
    for cidr in src_normalized:
        name = ip_to_object_name("src", cidr)
        addresses.append(AddressObject(name=name, value=cidr))
        src_names.append(name)

    dst_names: list[str] = []
    for cidr in dst_normalized:
        name = ip_to_object_name("dst", cidr)
        addresses.append(AddressObject(name=name, value=cidr))
        dst_names.append(name)

    applications: list[ApplicationObject] = []
    app_names: list[str] = []
    for spec, _kind in tcp_normalized:
        name = port_to_app_name("tcp", spec)
        applications.append(ApplicationObject(name=name, protocol="tcp", port_spec=spec))
        app_names.append(name)
    for spec, _kind in udp_normalized:
        name = port_to_app_name("udp", spec)
        applications.append(ApplicationObject(name=name, protocol="udp", port_spec=spec))
        app_names.append(name)

    policy = GeneratedPolicy(
        name=policy_input.name.strip(),
        from_zone=policy_input.from_zone.strip(),
        to_zone=policy_input.to_zone.strip(),
        source_addresses=src_names,
        destination_addresses=dst_names,
        applications=app_names,
        action=policy_input.action,
        description=policy_input.description,
    )
    return addresses, applications, policy


def render_set(policy_input: PolicyInput) -> Tuple[str, list[AddressObject], list[ApplicationObject], GeneratedPolicy]:
    """Validate input and render the full set-command block.

    Returns (set_commands, addresses, applications, policy).
    Raises ValidationError on bad input.
    """
    validate_policy_name(policy_input.name)
    validate_zone(policy_input.from_zone, "from_zone")
    validate_zone(policy_input.to_zone, "to_zone")

    addresses, applications, policy = _build_objects(policy_input)

    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(
        loader=FileSystemLoader(template_dir),
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    template = env.get_template("policy.set.j2")

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    output = template.render(
        timestamp=timestamp,
        policy=policy,
        addresses=addresses,
        applications=applications,
    )
    return output, addresses, applications, policy
