"""Pydantic data models for the policy generator."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class PolicyInput(BaseModel):
    """Raw user input from the form."""

    name: str = Field(..., min_length=1, max_length=63)
    from_zone: str = Field(..., min_length=1, max_length=63)
    to_zone: str = Field(..., min_length=1, max_length=63)
    src_ips: list[str] = Field(default_factory=list)
    dst_ips: list[str] = Field(default_factory=list)
    tcp_ports: list[str] = Field(default_factory=list)
    udp_ports: list[str] = Field(default_factory=list)
    action: Literal["permit", "deny"] = "permit"
    description: str = ""


class AddressObject(BaseModel):
    """Auto-generated address object (will be created on the SRX)."""

    name: str
    value: str  # normalized CIDR, e.g. "10.20.0.0/24"


class ApplicationObject(BaseModel):
    """Auto-generated application object (will be created on the SRX)."""

    name: str
    protocol: Literal["tcp", "udp"]
    port_spec: str  # "443" or "8000-8100"


class GeneratedPolicy(BaseModel):
    """The final policy referencing the generated objects."""

    name: str
    from_zone: str
    to_zone: str
    source_addresses: list[str] = Field(default_factory=list)
    destination_addresses: list[str] = Field(default_factory=list)
    applications: list[str] = Field(default_factory=list)
    action: str
    description: str = ""


class GenerateResponse(BaseModel):
    ok: bool
    set_commands: str = ""
    error: str = ""
    addresses: list[AddressObject] = Field(default_factory=list)
    applications: list[ApplicationObject] = Field(default_factory=list)
    policy: GeneratedPolicy | None = None
