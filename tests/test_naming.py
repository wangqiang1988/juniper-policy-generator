"""Tests for naming and normalization rules."""
from __future__ import annotations

import pytest

from poac.naming import (
    cidr_was_normalized,
    ip_to_object_name,
    normalize_cidr,
    parse_port_spec,
    port_to_app_name,
)


class TestNormalizeCidr:
    def test_single_ip_no_prefix(self) -> None:
        assert normalize_cidr("10.20.0.5") == "10.20.0.5/32"

    def test_single_ip_ipv6_no_prefix(self) -> None:
        assert normalize_cidr("2001:db8::1") == "2001:db8::1/128"

    def test_cidr_with_host_bits_normalized(self) -> None:
        assert normalize_cidr("10.20.0.5/24") == "10.20.0.0/24"
        assert normalize_cidr("10.20.0.1/24") == "10.20.0.0/24"

    def test_cidr_already_canonical(self) -> None:
        assert normalize_cidr("10.20.0.0/24") == "10.20.0.0/24"

    def test_cidr_explicit_32(self) -> None:
        assert normalize_cidr("10.20.0.5/32") == "10.20.0.5/32"

    def test_cidr_ipv6_normalized(self) -> None:
        assert normalize_cidr("2001:db8::1/64") == "2001:db8::/64"

    def test_whitespace_stripped(self) -> None:
        assert normalize_cidr("  10.20.0.5  ") == "10.20.0.5/32"

    def test_invalid_ip_raises(self) -> None:
        with pytest.raises(ValueError):
            normalize_cidr("999.999.999.999")

    def test_empty_raises(self) -> None:
        with pytest.raises(ValueError):
            normalize_cidr("")

    def test_garbage_raises(self) -> None:
        with pytest.raises(ValueError):
            normalize_cidr("not-an-ip")


class TestCidrWasNormalized:
    def test_changed(self) -> None:
        assert cidr_was_normalized("10.20.0.5/24") is True
        assert cidr_was_normalized("10.20.0.5") is True

    def test_not_changed(self) -> None:
        assert cidr_was_normalized("10.20.0.0/24") is False
        assert cidr_was_normalized("10.20.0.5/32") is False

    def test_invalid_input(self) -> None:
        assert cidr_was_normalized("garbage") is False


class TestIpToObjectName:
    def test_src(self) -> None:
        assert ip_to_object_name("src", "10.20.0.0/24") == "10.20.0.0/24"

    def test_dst(self) -> None:
        assert ip_to_object_name("dst", "203.0.113.10") == "203.0.113.10/32"

    def test_ipv6(self) -> None:
        assert ip_to_object_name("src", "2001:db8::/64") == "2001:db8::/64"

    def test_input_is_normalized(self) -> None:
        assert ip_to_object_name("src", "10.20.0.5/24") == "10.20.0.0/24"
        assert ip_to_object_name("src", "10.20.0.5") == "10.20.0.5/32"


class TestParsePortSpec:
    def test_single(self) -> None:
        assert parse_port_spec("443") == ("443", "single")

    def test_range(self) -> None:
        assert parse_port_spec("8000-8100") == ("8000-8100", "range")

    def test_invalid_range_inverted(self) -> None:
        with pytest.raises(ValueError):
            parse_port_spec("8100-8000")

    def test_invalid_range_equal(self) -> None:
        with pytest.raises(ValueError):
            parse_port_spec("8000-8000")

    def test_out_of_range_high(self) -> None:
        with pytest.raises(ValueError):
            parse_port_spec("70000")

    def test_out_of_range_low(self) -> None:
        with pytest.raises(ValueError):
            parse_port_spec("0")

    def test_non_integer(self) -> None:
        with pytest.raises(ValueError):
            parse_port_spec("abc")

    def test_too_many_dashes(self) -> None:
        with pytest.raises(ValueError):
            parse_port_spec("1-2-3")

    def test_empty(self) -> None:
        with pytest.raises(ValueError):
            parse_port_spec("")


class TestPortToAppName:
    def test_single(self) -> None:
        assert port_to_app_name("tcp", "443") == "tcp-443"

    def test_range(self) -> None:
        assert port_to_app_name("tcp", "8000-8100") == "tcp-8000-to-8100"

    def test_udp(self) -> None:
        assert port_to_app_name("udp", "53") == "udp-53"
