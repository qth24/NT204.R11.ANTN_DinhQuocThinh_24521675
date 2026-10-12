"""Canonical bidirectional 5-tuple and flow_id.

A packet A->B and its reply B->A must map to the same flow, so the two
endpoints (ip, port) are put in a fixed order (the "lower" one first):

    canonical key = (PROTO, lo_ip, lo_port, hi_ip, hi_port)

Endpoints are compared as (IP version, IP as integer, port), so the order
does not depend on how the IP text was written.

flow_id = "{PROTO}-{sha1(key)[:12]}-{seq}"
* the hash part is stable: same 5-tuple -> same prefix in every run
* seq starts at 1 and grows when the same 5-tuple starts a NEW session
  after the previous one closed/expired, so two sessions never share an ID
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class FlowKey:
    """Canonical (direction-independent) 5-tuple."""

    protocol: str
    lo_ip: str
    lo_port: int
    hi_ip: str
    hi_port: int

    def digest(self) -> str:
        """First 12 hex chars of SHA-1 over "PROTO|lo_ip|lo_port|hi_ip|hi_port"."""
        text = (
            f"{self.protocol}|{self.lo_ip}|{self.lo_port}|{self.hi_ip}|{self.hi_port}"
        )
        return hashlib.sha1(text.encode("ascii")).hexdigest()[:12]


def make_flow_key(
    protocol: str, src_ip: str, src_port: int, dst_ip: str, dst_port: int
) -> FlowKey:
    """Build the canonical key; both directions of a conversation give the same key.

    Raises ValueError if an IP address is not valid.
    """
    src = (_sort_key(src_ip, src_port), str(ipaddress.ip_address(src_ip)), src_port)
    dst = (_sort_key(dst_ip, dst_port), str(ipaddress.ip_address(dst_ip)), dst_port)
    lo, hi = (src, dst) if src[0] <= dst[0] else (dst, src)
    return FlowKey(protocol.upper(), lo[1], lo[2], hi[1], hi[2])


def make_flow_id(key: FlowKey, seq: int) -> str:
    """'TCP-3f2a9c1b7d4e-1'"""
    return f"{key.protocol}-{key.digest()}-{seq}"


def _sort_key(ip: str, port: int) -> tuple[int, int, int]:
    address = ipaddress.ip_address(ip)
    return (address.version, int(address), port)
