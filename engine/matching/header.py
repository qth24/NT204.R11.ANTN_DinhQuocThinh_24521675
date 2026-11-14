"""Header matcher: protocol, IP/CIDR, ports and direction of the CURRENT packet.

Pure function, no state. It looks only at the header of the packet being
evaluated; whether the packet goes to the server or to the client in the
*flow* is the flow matcher's job (they are independent).

    ->   src_rule matches src_event AND dst_rule matches dst_event
    <>   the line above, OR the reversed pair
         (src_rule vs dst_event AND dst_rule vs src_event)
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import IPv4Address, IPv4Network, ip_address
from typing import Any

from engine.rule_model import PortRange, Rule


def match_header(rule: Rule, event: dict[str, Any]) -> str | None:
    """Return None when the header matches, else the reason it does not."""
    header = rule.header
    if _protocol(event) != header.proto:
        return "protocol"
    src_ip, dst_ip = _ip(event, "src_ip"), _ip(event, "dst_ip")
    src_port, dst_port = _port(event, "src_port"), _port(event, "dst_port")

    if _side_matches(header.src_nets, header.src_ports, src_ip, src_port) and (
        _side_matches(header.dst_nets, header.dst_ports, dst_ip, dst_port)
    ):
        return None
    if header.direction == "<>" and (
        _side_matches(header.src_nets, header.src_ports, dst_ip, dst_port)
        and _side_matches(header.dst_nets, header.dst_ports, src_ip, src_port)
    ):
        return None
    return "direction" if header.direction == "->" else "address_or_port"


def _side_matches(
    nets: tuple[IPv4Network, ...],
    ports: tuple[PortRange, ...],
    ip: IPv4Address | None,
    port: int | None,
) -> bool:
    """One endpoint of the rule against one endpoint of the packet.

    Empty ``nets`` / ``ports`` mean ``any``. A packet whose IP or port is
    missing cannot satisfy a rule that constrains it.
    """
    if nets and (ip is None or not any(ip in net for net in nets)):
        return False
    if ports and (port is None or not any(r.contains(port) for r in ports)):
        return False
    return True


def _protocol(event: dict[str, Any]) -> str:
    normalized = event.get("normalized")
    if isinstance(normalized, dict) and normalized.get("protocol"):
        return str(normalized["protocol"]).upper()
    return str(event.get("protocol") or "").upper()


def _ip(event: dict[str, Any], name: str) -> IPv4Address | None:
    normalized = event.get("normalized")
    value = event.get(name)
    if isinstance(normalized, dict) and normalized.get(name):
        value = normalized[name]
    return _parse_ip(value) if isinstance(value, str) else None


@lru_cache(maxsize=4096)
def _parse_ip(text: str) -> IPv4Address | None:
    try:
        address = ip_address(text)
    except ValueError:
        return None
    return address if isinstance(address, IPv4Address) else None


def _port(event: dict[str, Any], name: str) -> int | None:
    port = event.get(name)
    return port if isinstance(port, int) and not isinstance(port, bool) else None
