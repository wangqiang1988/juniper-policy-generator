"""Tests for the renderer (full end-to-end)."""
from __future__ import annotations

import pytest

from juniper_policy_generator.models import PolicyInput
from juniper_policy_generator.renderer import render_set
from juniper_policy_generator.validator import ValidationError


def _render(p: PolicyInput) -> str:
    set_cmds, _a, _b, _c = render_set(p)
    return set_cmds


class TestRenderSetHappyPath:
    def test_minimal_policy(self) -> None:
        """A policy with only a single source IP and a single TCP port."""
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            src_ips=["10.0.0.0/24"],
            tcp_ports=["443"],
        )
        out = _render(p)
        # Address object: name == value
        assert "set security address-book global address 10.0.0.0/24 10.0.0.0/24" in out
        # Application
        assert "set applications application tcp-443 protocol tcp destination-port 443" in out
        # Policy
        assert "set security policies from-zone trust to-zone untrust policy p1" in out
        assert "match source-address 10.0.0.0/24" in out
        assert "match application tcp-443" in out
        assert "then permit" in out
        assert "then count" not in out

    def test_full_example(self) -> None:
        """The example from the README / sample output."""
        p = PolicyInput(
            name="sales-chi-to-sfdc",
            from_zone="users-chi",
            to_zone="internet",
            src_ips=["10.20.0.0/16", "10.21.0.0/16"],
            dst_ips=["203.0.113.0/24"],
            tcp_ports=["443", "8443"],
            action="permit",
            description="Sales team Chicago office -> Salesforce HTTPS",
        )
        out = _render(p)
        # Address names == values
        assert "address 10.20.0.0/16 10.20.0.0/16" in out
        assert "address 10.21.0.0/16 10.21.0.0/16" in out
        assert "address 203.0.113.0/24 203.0.113.0/24" in out
        # Application names
        assert "application tcp-443 protocol tcp" in out
        assert "application tcp-8443 protocol tcp" in out
        # Description
        assert 'description "Sales team Chicago office -> Salesforce HTTPS"' in out
        # Action
        assert "then permit" in out
        # No count
        assert "then count" not in out

    def test_cidr_normalization_in_output(self) -> None:
        """Host bits set in input must show normalized form in output."""
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            src_ips=["10.20.0.5/24"],
        )
        out = _render(p)
        assert "address 10.20.0.0/24 10.20.0.0/24" in out
        assert "10.20.0.5/24" not in out  # original host-bit form gone

    def test_single_ip_appended_32(self) -> None:
        """A bare IP must appear with /32 in the output."""
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            src_ips=["10.20.0.5"],
        )
        out = _render(p)
        assert "address 10.20.0.5/32 10.20.0.5/32" in out
        assert "match source-address 10.20.0.5/32" in out

    def test_port_range(self) -> None:
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            dst_ips=["10.0.0.0/24"],
            tcp_ports=["8000-8100"],
        )
        out = _render(p)
        assert "application tcp-8000-to-8100 protocol tcp" in out
        assert "destination-port 8000-8100" in out

    def test_udp_port(self) -> None:
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            dst_ips=["8.8.8.8"],
            udp_ports=["53"],
        )
        out = _render(p)
        assert "application udp-53 protocol udp" in out
        assert "protocol udp" in out

    def test_deny_action(self) -> None:
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            dst_ips=["10.0.0.0/24"],
            action="deny",
        )
        out = _render(p)
        assert "then deny" in out
        assert "then permit" not in out
        assert "then count" not in out

    def test_no_description(self) -> None:
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            dst_ips=["10.0.0.0/24"],
        )
        out = _render(p)
        assert "description" not in out
        # Policy line still present, just no description
        assert "set security policies from-zone trust to-zone untrust policy p1" in out

    def test_no_count_clause_anywhere(self) -> None:
        """Global check: `then count` must never appear, regardless of inputs."""
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            src_ips=["10.0.0.0/24", "10.1.0.0/24"],
            dst_ips=["203.0.113.0/24"],
            tcp_ports=["443", "8000-8100"],
            udp_ports=["53"],
        )
        out = _render(p)
        assert "then count" not in out


class TestRenderSetOrder:
    def test_addresses_before_apps_before_policy(self) -> None:
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            src_ips=["10.0.0.0/24"],
            dst_ips=["203.0.113.0/24"],
            tcp_ports=["443"],
            udp_ports=["53"],
        )
        out = _render(p)
        addr_pos = out.index("set security address-book")
        app_pos = out.index("set applications application")
        pol_pos = out.index("set security policies from-zone")
        assert addr_pos < app_pos < pol_pos


class TestRenderSetValidation:
    def test_empty_input_rejected(self) -> None:
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
        )
        with pytest.raises(ValidationError):
            _render(p)

    def test_bad_policy_name(self) -> None:
        p = PolicyInput(
            name="BadName",
            from_zone="trust",
            to_zone="untrust",
            dst_ips=["10.0.0.0/24"],
        )
        with pytest.raises(ValidationError):
            _render(p)

    def test_bad_ip(self) -> None:
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            dst_ips=["not-an-ip"],
        )
        with pytest.raises(ValidationError):
            _render(p)

    def test_bad_port(self) -> None:
        p = PolicyInput(
            name="p1",
            from_zone="trust",
            to_zone="untrust",
            dst_ips=["10.0.0.0/24"],
            tcp_ports=["99999"],
        )
        with pytest.raises(ValidationError):
            _render(p)
