"""Common output type of the capture layer.

Both live capture and PCAP import produce ``RawPacket`` objects, so the rest
of the pipeline never needs to know where a packet came from.
"""

from __future__ import annotations

from dataclasses import dataclass

# Common DLT/LINKTYPE numbers (see https://www.tcpdump.org/linktypes.html)
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LINUX_SLL = 113


class CaptureError(Exception):
    """Raised when a capture source cannot be opened (bad file, no permission...)."""


@dataclass(frozen=True)
class RawPacket:
    """A captured frame before any protocol parsing.

    Fields:
        timestamp: capture time, Unix epoch seconds (float).
        data: raw bytes of the frame, starting at the link-layer header.
        linktype: DLT number telling the parser how to decode ``data``.
        wire_len: original length on the wire (may be > len(data)).
        truncated: True if fewer bytes were captured than were on the wire
            (snaplen limit or a PCAP file cut in the middle of a record).
        source: human-readable origin, e.g. "live:eth0" or "pcap:test.pcap".
    """

    timestamp: float
    data: bytes
    linktype: int
    wire_len: int
    truncated: bool = False
    source: str = ""
