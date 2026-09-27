"""Capture live traffic from a network interface into ``RawPacket`` objects."""

from __future__ import annotations

import logging
import queue
from collections.abc import Iterator

from scapy.config import conf
from scapy.packet import Packet
from scapy.sendrecv import AsyncSniffer

from capture.raw_packet import LINKTYPE_ETHERNET, CaptureError, RawPacket

logger = logging.getLogger(__name__)

# How often the consumer loop wakes up to check whether the sniffer stopped.
_POLL_INTERVAL = 0.5


def live_packets(
    interface: str,
    bpf_filter: str | None = None,
    count: int = 0,
    timeout: float | None = None,
) -> Iterator[RawPacket]:
    """Sniff ``interface`` and yield each frame as a ``RawPacket``.

    Input:
        interface: NIC name (e.g. "eth0").
        bpf_filter: optional BPF filter, e.g. "tcp port 80".
        count: stop after this many packets (0 = unlimited).
        timeout: stop after this many seconds (None = until Ctrl+C).
    Output: iterator of RawPacket with source="live:<interface>".

    Raises CaptureError if the interface cannot be opened (missing root
    privileges, unknown interface, invalid BPF filter...).

    Scapy's AsyncSniffer runs in a background thread and pushes packets into a
    queue; this generator pulls them out so the caller can use the same
    ``for raw in source`` loop as for PCAP files.
    """
    packets: queue.Queue[Packet] = queue.Queue()
    sniffer = AsyncSniffer(
        iface=interface,
        filter=bpf_filter,
        count=count,
        timeout=timeout,
        prn=packets.put,
        store=False,
    )
    source = f"live:{interface}"
    sniffer.start()
    try:
        while True:
            try:
                pkt = packets.get(timeout=_POLL_INTERVAL)
            except queue.Empty:
                if sniffer.thread is not None and sniffer.thread.is_alive():
                    continue
                # Sniffer thread ended (count/timeout reached or it crashed).
                if sniffer.exception is not None:
                    raise CaptureError(
                        f"Cannot capture on {interface}: {sniffer.exception}"
                    ) from sniffer.exception
                if packets.empty():
                    break
                continue
            raw = _to_raw_packet(pkt, source)
            if raw is not None:
                yield raw
    finally:
        # Also runs on Ctrl+C or when the consumer stops iterating early.
        if sniffer.running:
            try:
                sniffer.stop()
            except Exception as exc:  # noqa: BLE001 - never mask the real error
                logger.debug("Error while stopping sniffer: %s", exc)


def _to_raw_packet(pkt: Packet, source: str) -> RawPacket | None:
    """Turn a Scapy packet from the sniffer back into raw bytes + linktype."""
    try:
        # ``original`` keeps the exact bytes received from the socket;
        # bytes(pkt) would re-build (and possibly "fix") a malformed packet.
        data = pkt.original if pkt.original is not None else bytes(pkt)
        linktype = conf.l2types.layer2num.get(type(pkt), LINKTYPE_ETHERNET)
        return RawPacket(
            timestamp=float(pkt.time),
            data=data,
            linktype=linktype,
            wire_len=getattr(pkt, "wirelen", None) or len(data),
            truncated=False,
            source=source,
        )
    except Exception as exc:  # noqa: BLE001 - one bad packet must not stop capture
        logger.warning("Dropping unreadable live packet: %s", exc)
        return None
