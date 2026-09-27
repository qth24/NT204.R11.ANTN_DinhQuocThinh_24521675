"""Transport layer parser: decode TCP or UDP headers.

Input: IP protocol number + the IPv4 payload (from ``parsers.network``).
Output: ``TransportLayer`` with ports, TCP flags/sequence numbers and the
application payload.

Like the network parser it never raises: problems go to ``error``.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

IP_PROTO_TCP = 6
IP_PROTO_UDP = 17

TCP_MIN_HEADER_LEN = 20
UDP_HEADER_LEN = 8

# src port, dst port, seq, ack, data offset (+NS bit), flags, window,
# checksum, urgent pointer
_TCP_HEADER = struct.Struct("!HHIIBBHHH")
# src port, dst port, length, checksum
_UDP_HEADER = struct.Struct("!HHHH")

# TCP flag bits of byte 13, lowest bit first
_TCP_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


@dataclass
class TransportLayer:
    """Result of the transport layer parser.

    Fields:
        protocol: "TCP", "UDP" or "UNKNOWN".
        src_port / dst_port: port numbers (None if the header is missing).
        tcp_flags: TCP flag names, e.g. ["SYN", "ACK"] (TCP only).
        seq / ack / window: TCP sequence number, ack number, window size.
        header_length: TCP header length incl. options, or 8 for UDP.
        udp_length: value of the UDP length field (header + data).
        payload: application data after the transport header.
        error: description of the problem if parsing failed or was partial.
    """

    protocol: str = "UNKNOWN"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: list[str] = field(default_factory=list)
    seq: int | None = None
    ack: int | None = None
    window: int | None = None
    header_length: int | None = None
    udp_length: int | None = None
    payload: bytes = b""
    error: str | None = None


def parse_transport(
    protocol: int | None, data: bytes, fragment_offset: int = 0
) -> TransportLayer:
    """Dispatch to the TCP or UDP parser based on the IP protocol number.

    Input:
        protocol: IP protocol number from the IPv4 header (6 = TCP, 17 = UDP).
        data: IPv4 payload.
        fragment_offset: IPv4 fragment offset in bytes. Only the first
            fragment (offset 0) carries the transport header.
    Output: TransportLayer; protocol "UNKNOWN" for anything but TCP/UDP.
    """
    if protocol == IP_PROTO_TCP:
        name = "TCP"
    elif protocol == IP_PROTO_UDP:
        name = "UDP"
    else:
        return TransportLayer(error=f"Unsupported transport protocol: {protocol}")

    if fragment_offset > 0:
        # Later fragments only contain a slice of the data, no header.
        return TransportLayer(
            protocol=name,
            payload=data,
            error=f"Non-first IP fragment (offset {fragment_offset}): "
            f"no {name} header",
        )

    return parse_tcp(data) if name == "TCP" else parse_udp(data)


def parse_tcp(data: bytes) -> TransportLayer:
    """Decode a TCP header (RFC 9293).

    Input: bytes starting at the TCP header.
    Output: TransportLayer with ports, flags, seq/ack, window and payload.
    """
    if len(data) < TCP_MIN_HEADER_LEN:
        return TransportLayer(
            protocol="TCP",
            error=f"Truncated TCP header: {len(data)} bytes "
            f"(need at least {TCP_MIN_HEADER_LEN})",
        )

    (
        src_port,
        dst_port,
        seq,
        ack,
        offset_byte,
        flag_byte,
        window,
        _checksum,
        _urgent,
    ) = _TCP_HEADER.unpack_from(data)

    header_length = (offset_byte >> 4) * 4  # data offset counts 32-bit words
    flags = [name for bit, name in _TCP_FLAG_BITS if flag_byte & bit]
    if offset_byte & 0x01:  # NS bit (RFC 3540) sits in the data offset byte
        flags.append("NS")

    result = TransportLayer(
        protocol="TCP",
        src_port=src_port,
        dst_port=dst_port,
        tcp_flags=flags,
        seq=seq,
        ack=ack,
        window=window,
        header_length=header_length,
    )

    if header_length < TCP_MIN_HEADER_LEN:
        result.error = f"Invalid TCP data offset: header length {header_length}"
        return result
    if header_length > len(data):
        result.error = (
            f"Truncated TCP options: header length {header_length}, "
            f"only {len(data)} bytes captured"
        )
        return result

    result.payload = data[header_length:]
    return result


def parse_udp(data: bytes) -> TransportLayer:
    """Decode a UDP header (RFC 768).

    Input: bytes starting at the UDP header.
    Output: TransportLayer with ports, udp_length and payload (cut to the
    length field).
    """
    if len(data) < UDP_HEADER_LEN:
        return TransportLayer(
            protocol="UDP",
            error=f"Truncated UDP header: {len(data)} bytes (need {UDP_HEADER_LEN})",
        )

    src_port, dst_port, length, _checksum = _UDP_HEADER.unpack_from(data)
    result = TransportLayer(
        protocol="UDP",
        src_port=src_port,
        dst_port=dst_port,
        header_length=UDP_HEADER_LEN,
        udp_length=length,
    )

    if length < UDP_HEADER_LEN:
        result.error = f"Invalid UDP length {length} (smaller than header)"
        result.payload = data[UDP_HEADER_LEN:]
        return result
    if length > len(data):
        result.error = (
            f"Truncated UDP datagram: length {length}, "
            f"only {len(data)} bytes captured"
        )
    result.payload = data[UDP_HEADER_LEN:length]
    return result
