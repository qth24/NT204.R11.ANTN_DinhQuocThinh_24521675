"""Flow record and its statistics.

A Flow is one bidirectional conversation. Endpoint A is the initiator
(decided by the tracker), so:
    direction "forward"  = packet sent by A
    direction "backward" = packet sent by B

byte_count definition: sum of the IPv4 "total length" field of every packet
(IP header + transport header + payload; no Ethernet header/padding), so the
value does not depend on the capture link type.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from flow.flow_key import FlowKey

FORWARD = "forward"
BACKWARD = "backward"


@dataclass(frozen=True)
class Endpoint:
    ip: str
    port: int


@dataclass
class Flow:
    """Mutable state of one active flow (owned by the FlowTracker)."""

    flow_id: str
    key: FlowKey
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    start_time: float
    last_seen: float
    state: str
    application_protocol: str | None = None
    packet_count: int = 0
    byte_count: int = 0
    fwd_packet_count: int = 0
    fwd_byte_count: int = 0
    bwd_packet_count: int = 0
    bwd_byte_count: int = 0
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    end_reason: str | None = None
    notes: list[str] = field(default_factory=list)

    @property
    def protocol(self) -> str:
        return self.key.protocol

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.start_time)

    def direction_of(self, src_ip: str, src_port: int) -> str:
        """'forward' if the packet comes from endpoint A, else 'backward'."""
        if (src_ip, src_port) == (self.endpoint_a.ip, self.endpoint_a.port):
            return FORWARD
        return BACKWARD

    def add_packet(
        self,
        direction: str,
        size: int,
        tcp_flags: list[str],
        timestamp: float,
        app_protocol: str | None,
    ) -> None:
        """Update every counter with one packet (pure ACKs included)."""
        self.packet_count += 1
        self.byte_count += size
        if direction == FORWARD:
            self.fwd_packet_count += 1
            self.fwd_byte_count += size
        else:
            self.bwd_packet_count += 1
            self.bwd_byte_count += size

        # One count per packet carrying the flag (TCP only; UDP has no flags)
        self.syn_count += "SYN" in tcp_flags
        self.ack_count += "ACK" in tcp_flags
        self.fin_count += "FIN" in tcp_flags
        self.rst_count += "RST" in tcp_flags

        # Timestamps may arrive slightly out of order: keep min/max
        self.start_time = min(self.start_time, timestamp)
        self.last_seen = max(self.last_seen, timestamp)

        # First application protocol seen in the flow wins
        if self.application_protocol is None and app_protocol:
            self.application_protocol = app_protocol

    def to_record(self) -> dict[str, Any]:
        """Line written to flows.jsonl."""
        return {
            "flow_id": self.flow_id,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "endpoint_a": {"ip": self.endpoint_a.ip, "port": self.endpoint_a.port},
            "endpoint_b": {"ip": self.endpoint_b.ip, "port": self.endpoint_b.port},
            "start_time": self.start_time,
            "last_seen": self.last_seen,
            "duration": round(self.duration, 6),
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "fwd_packet_count": self.fwd_packet_count,
            "fwd_byte_count": self.fwd_byte_count,
            "bwd_packet_count": self.bwd_packet_count,
            "bwd_byte_count": self.bwd_byte_count,
            "syn_count": self.syn_count,
            "ack_count": self.ack_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "state": self.state,
            "end_reason": self.end_reason,
            "notes": list(self.notes),
        }
