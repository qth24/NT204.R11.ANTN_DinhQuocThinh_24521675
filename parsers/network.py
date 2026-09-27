"""Network layer parser: strip the link-layer header, then decode IPv4.

Input: raw frame bytes + DLT linktype (from ``capture.RawPacket``).
Output: ``NetworkLayer`` with IPv4 header fields and the transport payload.

The parser never raises: any problem is written to ``NetworkLayer.error`` so
the pipeline can still emit an event (protocol UNKNOWN) instead of crashing.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass, field

# --- Link layer -------------------------------------------------------------
LINKTYPE_NULL = 0  # BSD loopback: 4-byte address family
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101  # raw IP, no link header
LINKTYPE_RAW_ALT = 12  # DLT_RAW value on some BSDs
LINKTYPE_LINUX_SLL = 113  # Linux "cooked" capture v1 (tcpdump -i any)
LINKTYPE_IPV4 = 228  # raw IPv4
LINKTYPE_LINUX_SLL2 = 276  # Linux "cooked" capture v2

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_QINQ = 0x88A8
ETHERTYPE_IPV6 = 0x86DD

_ETHERTYPE_NAMES = {
    ETHERTYPE_IPV4: "IPv4",
    ETHERTYPE_ARP: "ARP",
    ETHERTYPE_IPV6: "IPv6",
    0x8035: "RARP",
    0x88CC: "LLDP",
}

# --- IPv4 -------------------------------------------------------------------
IPV4_MIN_HEADER_LEN = 20
IP_PROTO_ICMP = 1
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

_IP_PROTO_NAMES = {IP_PROTO_ICMP: "ICMP", IP_PROTO_TCP: "TCP", IP_PROTO_UDP: "UDP"}

# version/IHL, TOS, total length, id, flags/fragment offset, TTL, protocol,
# checksum, source address, destination address
_IPV4_HEADER = struct.Struct("!BBHHHBBH4s4s")


@dataclass
class NetworkLayer:
    """Result of the network layer parser.

    Fields:
        ethertype: EtherType found in the link layer (0x0800 = IPv4), if any.
        src_ip / dst_ip: dotted IPv4 addresses.
        protocol: IP protocol number (6 = TCP, 17 = UDP, ...).
        protocol_name: "TCP", "UDP", "ICMP" or "IP-<n>".
        ttl, total_length, header_length, identification, tos: header fields.
        flags: subset of ["DF", "MF"] (plus "RESERVED" if the evil bit is set).
        fragment_offset: offset in bytes (the raw field is in 8-byte units).
        checksum_valid: result of recomputing the header checksum.
        payload: bytes after the IPv4 header, cut to ``total_length``
            (this removes Ethernet padding).
        error: description of the problem if parsing failed or was partial.
    """

    ethertype: int | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: int | None = None
    protocol_name: str | None = None
    ttl: int | None = None
    tos: int | None = None
    total_length: int | None = None
    header_length: int | None = None
    identification: int | None = None
    flags: list[str] = field(default_factory=list)
    fragment_offset: int = 0
    checksum_valid: bool | None = None
    payload: bytes = b""
    error: str | None = None

    @property
    def is_ipv4(self) -> bool:
        """True when an IPv4 header was decoded (possibly with a warning)."""
        return self.src_ip is not None

    @property
    def is_fragment(self) -> bool:
        """True for any IP fragment (more fragments follow, or offset > 0)."""
        return "MF" in self.flags or self.fragment_offset > 0


def parse_network(data: bytes, linktype: int) -> NetworkLayer:
    """Strip the link-layer header of ``data`` and parse the IPv4 packet inside.

    Input: raw frame bytes and its DLT linktype.
    Output: NetworkLayer. Non-IPv4 traffic (ARP, IPv6, ...) returns a result
    with ``error`` set and ``is_ipv4`` False.
    """
    try:
        ethertype, l3 = strip_link_layer(data, linktype)
    except ValueError as exc:
        return NetworkLayer(error=f"Link layer: {exc}")

    if ethertype != ETHERTYPE_IPV4:
        name = _ETHERTYPE_NAMES.get(ethertype, "unknown")
        return NetworkLayer(
            ethertype=ethertype,
            error=f"Unsupported network protocol: {name} (0x{ethertype:04x})",
        )

    result = parse_ipv4(l3)
    result.ethertype = ethertype
    return result


def strip_link_layer(data: bytes, linktype: int) -> tuple[int, bytes]:
    """Remove the link-layer header.

    Input: frame bytes + DLT linktype.
    Output: (ethertype, layer-3 bytes). For raw-IP linktypes the ethertype is
    derived from the IP version nibble.
    Raises ValueError if the header is too short or the linktype is unknown.
    """
    if linktype == LINKTYPE_ETHERNET:
        return _strip_ethernet(data)

    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_ALT, LINKTYPE_IPV4):
        if not data:
            raise ValueError("empty raw IP packet")
        # No EtherType here: use the IP version nibble. Anything that is not
        # IPv6 goes to the IPv4 parser, which reports a bad version itself.
        version = data[0] >> 4
        return (ETHERTYPE_IPV6 if version == 6 else ETHERTYPE_IPV4), data

    if linktype == LINKTYPE_LINUX_SLL:
        # 16-byte header, protocol (EtherType) in the last 2 bytes
        _require(data, 16, "Linux SLL header")
        return struct.unpack_from("!H", data, 14)[0], data[16:]

    if linktype == LINKTYPE_LINUX_SLL2:
        # 20-byte header, protocol (EtherType) in the first 2 bytes
        _require(data, 20, "Linux SLL2 header")
        return struct.unpack_from("!H", data, 0)[0], data[20:]

    if linktype == LINKTYPE_NULL:
        # 4-byte address family in host byte order; AF_INET is 2 everywhere
        _require(data, 4, "BSD loopback header")
        family = int.from_bytes(data[:4], "little")
        if family > 0xFFFF:  # written by a big-endian host
            family = int.from_bytes(data[:4], "big")
        return (ETHERTYPE_IPV4 if family == 2 else 0), data[4:]

    raise ValueError(f"unsupported linktype {linktype}")


def _strip_ethernet(data: bytes) -> tuple[int, bytes]:
    """Ethernet II: 6B dst MAC, 6B src MAC, 2B EtherType; skip 802.1Q VLAN tags."""
    _require(data, 14, "Ethernet header")
    ethertype = struct.unpack_from("!H", data, 12)[0]
    offset = 14
    while ethertype in (ETHERTYPE_VLAN, ETHERTYPE_QINQ):
        # VLAN tag: 2B TCI, then the real EtherType
        _require(data, offset + 4, "802.1Q VLAN tag")
        ethertype = struct.unpack_from("!H", data, offset + 2)[0]
        offset += 4
    return ethertype, data[offset:]


def parse_ipv4(data: bytes) -> NetworkLayer:
    """Decode an IPv4 header (RFC 791).

    Input: bytes starting at the IPv4 header.
    Output: NetworkLayer. A header that is present but inconsistent with the
    captured length (truncated packet) still returns the header fields, with
    ``error`` describing the problem and ``payload`` holding what is available.
    """
    if len(data) < IPV4_MIN_HEADER_LEN:
        return NetworkLayer(
            error=f"Truncated IPv4 header: {len(data)} bytes "
            f"(need at least {IPV4_MIN_HEADER_LEN})"
        )

    (
        ver_ihl,
        tos,
        total_length,
        identification,
        flags_frag,
        ttl,
        protocol,
        _checksum,
        src,
        dst,
    ) = _IPV4_HEADER.unpack_from(data)

    version = ver_ihl >> 4
    if version != 4:
        return NetworkLayer(error=f"Invalid IP version {version} (expected 4)")

    header_length = (ver_ihl & 0x0F) * 4  # IHL counts 32-bit words
    if header_length < IPV4_MIN_HEADER_LEN:
        return NetworkLayer(error=f"Invalid IPv4 header length {header_length}")

    result = NetworkLayer(
        src_ip=str(ipaddress.IPv4Address(src)),
        dst_ip=str(ipaddress.IPv4Address(dst)),
        protocol=protocol,
        protocol_name=_IP_PROTO_NAMES.get(protocol, f"IP-{protocol}"),
        ttl=ttl,
        tos=tos,
        total_length=total_length,
        header_length=header_length,
        identification=identification,
        flags=_decode_flags(flags_frag),
        fragment_offset=(flags_frag & 0x1FFF) * 8,
    )

    if len(data) < header_length:
        result.error = (
            f"Truncated IPv4 options: header length {header_length}, "
            f"only {len(data)} bytes captured"
        )
        return result

    result.checksum_valid = _checksum_ok(data[:header_length])

    if total_length < header_length:
        result.error = (
            f"Invalid IPv4 total length {total_length} "
            f"(smaller than header length {header_length})"
        )
        result.payload = data[header_length:]
        return result

    if total_length > len(data):
        result.error = (
            f"Truncated IPv4 packet: total length {total_length}, "
            f"only {len(data)} bytes captured"
        )
    # Slicing to total_length drops Ethernet padding on short frames.
    result.payload = data[header_length:total_length]
    return result


def _decode_flags(flags_frag: int) -> list[str]:
    """The top 3 bits of the flags/fragment field: reserved, DF, MF."""
    flags = []
    if flags_frag & 0x8000:
        flags.append("RESERVED")
    if flags_frag & 0x4000:
        flags.append("DF")
    if flags_frag & 0x2000:
        flags.append("MF")
    return flags


def _checksum_ok(header: bytes) -> bool:
    """Internet checksum (RFC 1071): one's-complement sum of the header == 0xFFFF."""
    total = sum(struct.unpack(f"!{len(header) // 2}H", header))
    while total > 0xFFFF:
        total = (total & 0xFFFF) + (total >> 16)
    return total == 0xFFFF


def _require(data: bytes, length: int, what: str) -> None:
    if len(data) < length:
        raise ValueError(f"truncated {what}: {len(data)} bytes, need {length}")
