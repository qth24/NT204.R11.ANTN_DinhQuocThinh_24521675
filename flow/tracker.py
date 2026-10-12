"""FlowTracker: active flow table, per-packet update, expiry and flush.

Input:  event dicts (after Decoder + Preprocessor), in packet order.
Output: ``flow_id`` and ``direction`` written into each event, plus flow
        records (see ``Flow.to_record``) for every flow that is exported.

Time always comes from the packet timestamps (never ``time.time()``), so
replaying a PCAP gives the same flows every time; live capture uses the same
logic because live packets carry their capture timestamp too.

Life of a flow:
    1. first packet of a 5-tuple -> new Flow; endpoint A = sender of that
       packet (the SYN sender for TCP, or the first talker when the capture
       started mid-connection / for UDP)
    2. every packet updates counters (and the TCP state machine)
    3. the flow is exported to flows.jsonl and removed from the table when
       - it is idle longer than tcp_idle_timeout / udp_idle_timeout
         (end_reason "idle_timeout", UDP state becomes EXPIRED)
       - it is CLOSED / RESET and ``closed_linger`` has passed
         (end_reason "fin" / "rst")
       - a new SYN reuses the 5-tuple of a CLOSED/RESET flow
       - the table is full (max_active_flows): least recently seen flow is
         evicted (end_reason "evicted")
       - the capture ends: ``flush()`` (end_reason "end_of_capture")
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter
from typing import Any

from config import FlowConfig
from flow.flow import Endpoint, Flow
from flow.flow_key import FlowKey, make_flow_id, make_flow_key
from flow.tcp_state import (
    CLOSED,
    RESET,
    TERMINAL_STATES,
    TcpStateMachine,
    is_connection_start,
)

ACTIVE = "ACTIVE"
EXPIRED = "EXPIRED"
# Labels for flows of packets without ports when flow.portless = "zero"
_IP_PROTO_NAMES = {1: "ICMP", 2: "IGMP", 47: "GRE", 50: "ESP", 58: "ICMPV6"}


class FlowTracker:
    """Owns the active flow table (instance state, no module-level globals)."""

    def __init__(self, cfg: FlowConfig) -> None:
        self.cfg = cfg
        self._active: dict[FlowKey, Flow] = {}
        self._machines: dict[str, TcpStateMachine] = {}  # flow_id -> TCP state
        self._last_seq: dict[FlowKey, int] = {}  # last session number per 5-tuple
        self._last_sweep: float | None = None
        self.flows_created = 0
        self.end_reasons: Counter[str] = Counter()

    @property
    def active_count(self) -> int:
        return len(self._active)

    def active_flow_ids(self) -> list[str]:
        return [flow.flow_id for flow in self._active.values()]

    def process(self, event: dict[str, Any]) -> list[dict[str, Any]]:
        """Attach ``flow_id``/``direction`` to ``event``.

        Returns the records of flows exported while handling this packet
        (expired, closed or evicted ones). Never raises on bad input: an
        event that cannot belong to a flow just gets flow_id None.
        """
        event["flow_id"] = None
        event["direction"] = None
        timestamp = event.get("timestamp")
        if not _valid_time(timestamp):
            # NaN / inf / negative / non-number would break every timeout
            # comparison, so such events never join a flow.
            return []

        exported = self.sweep(float(timestamp))
        tuple_ = self._five_tuple(event)
        if tuple_ is None:
            return exported
        protocol, src_ip, src_port, dst_ip, dst_port = tuple_
        try:
            key = make_flow_key(protocol, src_ip, src_port, dst_ip, dst_port)
        except ValueError:
            return exported

        flags = event.get("tcp_flags")
        flags = flags if isinstance(flags, list) else []
        flow = self._active.get(key)
        if flow is not None:
            if self._is_expired(flow, timestamp):
                # Sweeps are rate-limited, so check this flow explicitly.
                exported.append(self._export(flow, self._expiry_reason(flow)))
                flow = None
            elif flow.state in TERMINAL_STATES and is_connection_start(flags):
                # New SYN on a finished connection = a new session (seq + 1).
                exported.append(self._export(flow, self._expiry_reason(flow)))
                flow = None
        if flow is None:
            if len(self._active) >= self.cfg.max_active_flows:
                oldest = min(self._active.values(), key=lambda f: f.last_seen)
                exported.append(self._export(oldest, "evicted"))
            flow = self._create(
                key, src_ip, src_port, dst_ip, dst_port, flags, timestamp
            )

        direction = flow.direction_of(_canonical_ip(src_ip), src_port)
        size = event.get("ip_total_length")
        flow.add_packet(
            direction,
            size if isinstance(size, int) and not isinstance(size, bool) else 0,
            flags,
            timestamp,
            _app_protocol(event),
        )
        machine = self._machines.get(flow.flow_id)
        if machine is not None:
            payload_length = event.get("payload_length")
            flow.state = machine.update(
                direction,
                flags,
                payload_length if isinstance(payload_length, int) else 0,
            )

        event["flow_id"] = flow.flow_id
        event["direction"] = direction
        return exported

    def sweep(self, now: float) -> list[dict[str, Any]]:
        """Export every flow whose timeout has passed at packet time ``now``.

        Runs at most once per ``flow.sweep_interval`` seconds of packet time.
        """
        if (
            self._last_sweep is not None
            and 0 <= now - self._last_sweep < self.cfg.sweep_interval
        ):
            return []
        self._last_sweep = now
        expired = [f for f in self._active.values() if self._is_expired(f, now)]
        return [self._export(flow, self._expiry_reason(flow)) for flow in expired]

    def flush(self) -> list[dict[str, Any]]:
        """End of capture / Ctrl+C: export every remaining flow."""
        remaining = list(self._active.values())
        return [
            self._export(
                flow,
                (
                    self._expiry_reason(flow)
                    if flow.state in TERMINAL_STATES
                    else "end_of_capture"
                ),
            )
            for flow in remaining
        ]

    # --- internals ----------------------------------------------------------

    def _five_tuple(
        self, event: dict[str, Any]
    ) -> tuple[str, str, int, str, int] | None:
        src_ip, dst_ip = event.get("src_ip"), event.get("dst_ip")
        if not isinstance(src_ip, str) or not isinstance(dst_ip, str):
            return None
        protocol = str(event.get("protocol") or "").upper()
        src_port, dst_port = event.get("src_port"), event.get("dst_port")
        has_ports = all(
            isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 65535
            for p in (src_port, dst_port)
        )
        if protocol in ("TCP", "UDP") and has_ports:
            return protocol, src_ip, src_port, dst_ip, dst_port
        if self.cfg.portless != "zero":
            return None  # "skip": packets without ports belong to no flow
        ip_protocol = event.get("ip_protocol")
        label = (
            protocol
            if protocol in ("TCP", "UDP")
            else _IP_PROTO_NAMES.get(
                ip_protocol,
                f"IP{ip_protocol}" if isinstance(ip_protocol, int) else "IP",
            )
        )
        return label, src_ip, 0, dst_ip, 0

    def _create(
        self,
        key: FlowKey,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        flags: list[str],
        timestamp: float,
    ) -> Flow:
        seq = self._last_seq.get(key, 0) + 1
        self._last_seq[key] = seq
        flow = Flow(
            flow_id=make_flow_id(key, seq),
            key=key,
            # The sender of the first packet is the initiator A.
            endpoint_a=Endpoint(_canonical_ip(src_ip), src_port),
            endpoint_b=Endpoint(_canonical_ip(dst_ip), dst_port),
            start_time=timestamp,
            last_seen=timestamp,
            state=ACTIVE,
        )
        if key.protocol == "TCP":
            machine = TcpStateMachine.start(flags)
            self._machines[flow.flow_id] = machine
            flow.state = machine.state
            if machine.midstream:
                flow.notes.append("midstream")
        self._active[key] = flow
        self.flows_created += 1
        return flow

    def _timeout(self, flow: Flow) -> float:
        if flow.state in TERMINAL_STATES:
            return self.cfg.closed_linger
        if flow.protocol == "TCP":
            return self.cfg.tcp_idle_timeout
        return self.cfg.udp_idle_timeout

    def _is_expired(self, flow: Flow, now: float) -> bool:
        return now - flow.last_seen > self._timeout(flow)

    @staticmethod
    def _expiry_reason(flow: Flow) -> str:
        if flow.state == CLOSED:
            return "fin"
        if flow.state == RESET:
            return "rst"
        return "idle_timeout"

    def _export(self, flow: Flow, reason: str) -> dict[str, Any]:
        """Remove ``flow`` from the active table and return its record."""
        flow.end_reason = reason
        if reason == "idle_timeout" and flow.state == ACTIVE:
            flow.state = EXPIRED  # UDP / port-less flows: ACTIVE -> EXPIRED
        del self._active[flow.key]
        self._machines.pop(flow.flow_id, None)
        self.end_reasons[reason] += 1
        return flow.to_record()


def _valid_time(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= 0
    )


def _app_protocol(event: dict[str, Any]) -> str | None:
    """Normalized (UPPERCASE) app protocol, so a flow never mixes 'http'/'HTTP'."""
    normalized = event.get("normalized")
    if isinstance(normalized, dict) and normalized.get("app_protocol"):
        return normalized["app_protocol"]
    raw = event.get("app_protocol")
    return raw.strip().upper() if isinstance(raw, str) and raw.strip() else None


def _canonical_ip(ip: str) -> str:
    """Same IP text as stored in FlowKey, so endpoint comparisons match."""
    return str(ipaddress.ip_address(ip))
