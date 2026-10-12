"""Pipeline orchestrator: RawPacket -> parsers of every layer -> IDSEvent.

    RawPacket
      -> parse_network      (link layer + IPv4)
      -> parse_transport    (TCP / UDP)
      -> detect_app_protocol
      -> parse_http / parse_dns / parse_smtp
      -> IDSEvent

The same ``Pipeline`` object is used for live capture and PCAP import: both
sources yield ``RawPacket`` objects.

BT2 stages run on the event as a dict (``enrich``), after the BT1 parsers:

    IDSEvent.to_dict() -> decode_event -> preprocess_event -> FlowTracker
"""

from __future__ import annotations

import logging
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from capture.raw_packet import RawPacket
from config import Config
from core.event import IDSEvent
from decoder import decode_event
from flow.tracker import FlowTracker
from parsers.app import AppResult
from parsers.app.dns_parser import parse_dns
from parsers.app.http_parser import parse_http
from parsers.app.smtp_parser import parse_smtp
from parsers.app_detector import detect_app_protocol
from parsers.network import NetworkLayer, parse_network
from parsers.transport import TransportLayer, parse_transport
from preprocess import preprocess_event

logger = logging.getLogger(__name__)

# Bytes of payload copied into IDSEvent.payload_preview
PAYLOAD_PREVIEW_BYTES = 128


@dataclass
class PipelineStats:
    """Counters reported at the end of a run."""

    processed: int = 0
    written: int = 0
    skipped: int = 0
    dropped: int = 0
    with_error: int = 0
    by_protocol: Counter[str] = field(default_factory=Counter)
    by_app_protocol: Counter[str] = field(default_factory=Counter)
    by_preprocess_status: Counter[str] = field(default_factory=Counter)
    flows_exported: int = 0
    flow_end_reasons: Counter[str] = field(default_factory=Counter)


class Pipeline:
    """Turn ``RawPacket`` objects into ``IDSEvent`` objects.

    Args:
        skip_unknown: if True, packets whose protocol is UNKNOWN (ARP, IPv6,
            ICMP, unreadable...) produce no event instead of an UNKNOWN event.
        config: BT2 settings (defaults when None).
    """

    def __init__(
        self, skip_unknown: bool = False, config: Config | None = None
    ) -> None:
        self.skip_unknown = skip_unknown
        self.config = config or Config()
        # The only mutable state: packet counter used for packet_id.
        # (The flow table lives inside the FlowTracker instance.)
        self._packet_counter = 0
        self._flows_exported = 0
        self._flow_end_reasons: Counter[str] = Counter()
        self.tracker = (
            FlowTracker(self.config.flow) if self.config.flow.enabled else None
        )

    def process(self, raw: RawPacket) -> IDSEvent | None:
        """BT1: parse one packet. Returns None only when skipped by config.

        Never raises: each layer is guarded separately so a failure in one
        layer keeps the fields already extracted by the previous ones.
        """
        event, _payload = self._parse(raw)
        if self.skip_unknown and event.protocol == "UNKNOWN":
            return None
        return event

    def process_bt2(
        self, raw: RawPacket, flow_sink: Callable[[dict[str, Any]], None] | None = None
    ) -> dict[str, Any] | None:
        """BT1 parsing followed by the BT2 stages; returns the event dict.

        None when the packet is skipped (``skip_unknown``) or dropped by the
        preprocessor without logging.
        """
        event, payload = self._parse(raw)
        if self.skip_unknown and event.protocol == "UNKNOWN":
            return None
        return self.enrich(event.to_dict(), payload, flow_sink)

    def enrich(
        self,
        event: dict[str, Any],
        payload: bytes | None = None,
        flow_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> dict[str, Any] | None:
        """Run the BT2 stages on one event dict (from a packet or a JSONL file).

        ``payload`` is the raw application payload when the event comes from
        a packet; it lets the decoder see the original bytes.
        Flows exported meanwhile (expired/closed/evicted) go to ``flow_sink``.
        Returns None when the event is dropped and not logged.
        """
        event = decode_event(event, self.config.decoder, payload)
        result = preprocess_event(event, self.config.preprocess)
        event["flow_id"] = None
        event["direction"] = None
        if result is None or result.get("processing_action") == "drop":
            return result  # dropped events never reach the flow tracker
        if self.tracker is not None:
            try:
                exported = self.tracker.process(event)
            except Exception as exc:  # must not stop the pipeline
                logger.exception(
                    "flow tracker failed on packet %s", event.get("packet_id")
                )
                event.setdefault("reason", []).append(f"flow_tracker_error:{exc}")
                exported = []
            for record in exported:
                self._flow_out(record, flow_sink)
        return event

    def flush_flows(
        self, flow_sink: Callable[[dict[str, Any]], None] | None = None
    ) -> None:
        """Export every flow still active (end of capture / Ctrl+C)."""
        if self.tracker is not None:
            for record in self.tracker.flush():
                self._flow_out(record, flow_sink)

    def _flow_out(
        self, record: dict[str, Any], flow_sink: Callable[[dict[str, Any]], None] | None
    ) -> None:
        self._flows_exported += 1
        self._flow_end_reasons[record["end_reason"]] += 1
        if flow_sink is not None:
            flow_sink(record)

    def _parse(self, raw: RawPacket) -> tuple[IDSEvent, bytes]:
        """Run the BT1 parsers; returns the event and the application payload."""
        self._packet_counter += 1
        event = IDSEvent(
            packet_id=self._packet_counter,
            timestamp=raw.timestamp,
            length=raw.wire_len,
            source=raw.source,
        )
        if raw.truncated:
            event.add_error(
                "capture",
                f"truncated packet ({len(raw.data)} of {raw.wire_len} bytes)",
            )

        payload = b""
        net = self._network_layer(raw, event)
        if net is not None and net.is_ipv4:
            transport = self._transport_layer(net, event)
            if transport is not None and transport.protocol != "UNKNOWN":
                self._application_layer(transport, event)
                payload = transport.payload

        if event.error:
            logger.info("packet %d: %s", event.packet_id, event.error)
        return event, payload

    def run(
        self, source: Iterable[RawPacket], sink: Callable[[IDSEvent], None]
    ) -> PipelineStats:
        """Process every packet of ``source`` and pass events to ``sink``."""
        stats = PipelineStats()
        for raw in source:
            stats.processed += 1
            event = self.process(raw)
            if event is None:
                stats.skipped += 1
                continue
            stats.written += 1
            stats.by_protocol[event.protocol] += 1
            if event.app_protocol:
                stats.by_app_protocol[event.app_protocol] += 1
            if event.error:
                stats.with_error += 1
            sink(event)
        return stats

    def run_bt2(
        self,
        source: Iterable[RawPacket],
        sink: Callable[[dict[str, Any]], None],
        flow_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> PipelineStats:
        """BT2: every packet through all stages; events -> ``sink``, flows -> ``flow_sink``.

        Remaining flows are flushed even if the loop is interrupted (Ctrl+C).
        """
        stats = PipelineStats()
        try:
            for raw in source:
                stats.processed += 1
                parsed, payload = self._parse(raw)
                if self.skip_unknown and parsed.protocol == "UNKNOWN":
                    stats.skipped += 1
                    continue
                event = self.enrich(parsed.to_dict(), payload, flow_sink)
                self._emit(event, stats, sink)
        finally:
            self.flush_flows(flow_sink)
            stats.flows_exported = self._flows_exported
            stats.flow_end_reasons = Counter(self._flow_end_reasons)
        return stats

    def _emit(
        self,
        event: dict[str, Any] | None,
        stats: PipelineStats,
        sink: Callable[[dict[str, Any]], None],
    ) -> None:
        """Count an enriched event and write it (dropped ones only if logged)."""
        if event is None or event.get("processing_action") == "drop":
            stats.dropped += 1
            if event is None:
                return
        _count(stats, event)
        sink(event)

    # --- one method per layer, each with its own try/except ---------------

    def _network_layer(self, raw: RawPacket, event: IDSEvent) -> NetworkLayer | None:
        try:
            net = parse_network(raw.data, raw.linktype)
        except Exception as exc:  # never stop on a parser bug
            logger.exception("network parser failed on packet %d", event.packet_id)
            event.add_error("network", f"internal error: {exc}")
            return None
        event.src_ip = net.src_ip
        event.dst_ip = net.dst_ip
        event.ip_protocol = net.protocol
        event.ip_total_length = net.total_length
        event.ttl = net.ttl
        event.add_error("network", net.error)
        return net

    def _transport_layer(
        self, net: NetworkLayer, event: IDSEvent
    ) -> TransportLayer | None:
        try:
            tr = parse_transport(net.protocol, net.payload, net.fragment_offset)
        except Exception as exc:
            logger.exception("transport parser failed on packet %d", event.packet_id)
            event.add_error("transport", f"internal error: {exc}")
            return None
        event.protocol = tr.protocol
        event.src_port = tr.src_port
        event.dst_port = tr.dst_port
        event.tcp_flags = tr.tcp_flags
        event.tcp_seq = tr.seq
        event.tcp_ack = tr.ack
        event.tcp_window = tr.window
        event.payload_length = len(tr.payload)
        event.add_error("transport", tr.error)
        return tr

    def _application_layer(self, tr: TransportLayer, event: IDSEvent) -> None:
        try:
            detection = detect_app_protocol(
                tr.protocol, tr.src_port, tr.dst_port, tr.payload
            )
            if detection.app_protocol is None:
                # Unparsed payload: keep a raw preview for signature matching.
                # Parsed protocols carry their data in app_data instead (so
                # e.g. SMTP AUTH credentials redacted there never leak here).
                event.payload_preview = _preview(tr.payload)
                return
            event.app_protocol = detection.app_protocol
            event.detected_by = detection.detected_by
            result = _parse_app(detection.app_protocol, tr)
        except Exception as exc:
            logger.exception("application parser failed on packet %d", event.packet_id)
            event.add_error("application", f"internal error: {exc}")
            return
        event.app_data = result.data
        event.add_error(detection.app_protocol.lower(), result.error)


def _count(stats: PipelineStats, event: dict[str, Any]) -> None:
    stats.written += 1
    stats.by_protocol[str(event.get("protocol"))] += 1
    if event.get("app_protocol"):
        stats.by_app_protocol[event["app_protocol"]] += 1
    if event.get("error"):
        stats.with_error += 1
    if event.get("preprocess_status"):
        stats.by_preprocess_status[event["preprocess_status"]] += 1


def _preview(payload: bytes) -> str | None:
    """Readable, JSON-safe view of the payload start (for signature matching)."""
    if not payload:
        return None
    chunk = payload[:PAYLOAD_PREVIEW_BYTES]
    return "".join(
        chr(b) if 32 <= b < 127 or b in (9, 10, 13) else f"\\x{b:02x}" for b in chunk
    )


def _parse_app(app_protocol: str, tr: TransportLayer) -> AppResult:
    """Call the application parser matching the detected protocol."""
    if app_protocol == "HTTP":
        return parse_http(tr.payload)
    if app_protocol == "DNS":
        return parse_dns(tr.payload, tcp=tr.protocol == "TCP")
    if app_protocol == "SMTP":
        return parse_smtp(tr.payload)
    return AppResult(error=f"no parser for {app_protocol}")
