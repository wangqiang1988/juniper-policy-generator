"""Tests for the validator module."""
from __future__ import annotations

import pytest

from juniper_policy_generator.validator import (
    ValidationError,
    normalize_ip_list,
    normalize_port_list,
    validate_input_has_content,
    validate_policy_name,
    validate_zone,
)


class TestValidatePolicyName:
    def test_valid(self) -> None:
        for n in ["p1", "sales-chi-to-sfdc", "abc_123", "a-b-c"]:
            validate_policy_name(n)  # should not raise

    def test_uppercase_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_policy_name("MyPolicy")

    def test_special_chars(self) -> None:
        with pytest.raises(ValidationError):
            validate_policy_name("policyname!")

    def test_too_long(self) -> None:
        with pytest.raises(ValidationError):
            validate_policy_name("a" * 64)

    def test_empty(self) -> None:
        with pytest.raises(ValidationError):
            validate_policy_name("")


class TestValidateZone:
    def test_valid(self) -> None:
        for z in ["trust", "untrust", "users-chi", "vlan.100"]:
            validate_zone(z, "from_zone")

    def test_empty_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_zone("", "from_zone")

    def test_invalid_chars(self) -> None:
        with pytest.raises(ValidationError):
            validate_zone("zone with space", "from_zone")


class TestNormalizeIpList:
    def test_normalizes_and_dedups_blanks(self) -> None:
        assert normalize_ip_list(["10.0.0.1", "", "  ", "10.1.0.5/24"]) == [
            "10.0.0.1/32",
            "10.1.0.0/24",
        ]

    def test_invalid_propagates(self) -> None:
        with pytest.raises(ValidationError):
            normalize_ip_list(["not-an-ip"])


class TestNormalizePortList:
    def test_mixed(self) -> None:
        assert normalize_port_list(["443", "", "8000-8100"]) == [
            ("443", "single"),
            ("8000-8100", "range"),
        ]

    def test_invalid(self) -> None:
        with pytest.raises(ValidationError):
            normalize_port_list(["abc"])


class TestValidateInputHasContent:
    def test_empty_raises(self) -> None:
        with pytest.raises(ValidationError):
            validate_input_has_content([], [], [], [])

    def test_src_only(self) -> None:
        validate_input_has_content(["10.0.0.0/24"], [], [], [])

    def test_dst_only(self) -> None:
        validate_input_has_content([], ["10.0.0.0/24"], [], [])

    def test_tcp_only(self) -> None:
        validate_input_has_content([], [], ["443"], [])

    def test_udp_only(self) -> None:
        validate_input_has_content([], [], [], ["53"])
