"""Normalized IDS Event: the only data structure later IDS stages consume.

Detection engines (port scan detection, alerting...) read these events and
never touch Scapy objects or raw bytes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class IDSEvent:
    """One parsed packet.

    Required fields (assignment schema):
        packet_id: sequence number assigned by the pipeline (starts at 1).
        timestamp: capture time, Unix epoch seconds.
        src_ip / dst_ip: IPv4 addresses (None if the IPv4 header is unreadable).
        protocol: "TCP", "UDP" or "UNKNOWN".
        src_port / dst_port: transport ports (None when not available).
        tcp_flags: e.g. ["SYN", "ACK"]; empty for non-TCP packets.
        app_protocol: "HTTP", "DNS", "SMTP" or None.
        app_data: protocol-specific dict produced by the application parser.
        error: parse problems of every layer ("network: ...; transport: ..."),
            None for a clean packet.

    Extra context fields:
        length: original frame length on the wire.
        ip_protocol: IP protocol number (1 = ICMP, 6 = TCP, 17 = UDP...).
        ip_total_length: IPv4 "total length" field (IP header + payload);
            used as the byte count of flows (BT2).
        ttl: IPv4 time-to-live.
        tcp_seq / tcp_ack / tcp_window: TCP header values.
        payload_length: bytes of application payload.
        payload_preview: first bytes of a payload that no application parser
            handled, as text; non-printable bytes are shown as \\xNN (None
            when there is no payload or app_protocol is set).
        detected_by: "payload" or "port" (how app_protocol was recognised).
        source: "live:<iface>" or "pcap:<file>".
    """

    packet_id: int
    timestamp: float
    src_ip: str | None = None
    dst_ip: str | None = None
    protocol: str = "UNKNOWN"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: list[str] = field(default_factory=list)
    app_protocol: str | None = None
    app_data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    length: int = 0
    ip_protocol: int | None = None
    ip_total_length: int | None = None
    ttl: int | None = None
    tcp_seq: int | None = None
    tcp_ack: int | None = None
    tcp_window: int | None = None
    payload_length: int = 0
    payload_preview: str | None = None
    detected_by: str | None = None
    source: str = ""

    def add_error(self, layer: str, message: str | None) -> None:
        """Append ``message`` (if any) to ``error``, prefixed by the layer name."""
        if not message:
            return
        entry = f"{layer}: {message}"
        self.error = entry if self.error is None else f"{self.error}; {entry}"

    def to_dict(self) -> dict[str, Any]:
        """Plain dict ready for ``json.dumps``."""
        return asdict(self)
