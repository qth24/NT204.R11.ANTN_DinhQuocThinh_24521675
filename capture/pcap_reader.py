"""Read packets from a PCAP / PCAPNG file into ``RawPacket`` objects."""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator

from scapy.error import Scapy_Exception
from scapy.utils import RawPcapNgReader, RawPcapReader

from capture.raw_packet import CaptureError, RawPacket

logger = logging.getLogger(__name__)


def read_pcap(path: str) -> Iterator[RawPacket]:
    """Yield every packet of a PCAP/PCAPNG file as a ``RawPacket``.

    Input: path to a .pcap or .pcapng file.
    Output: iterator of RawPacket (timestamp, data, linktype, wire_len, truncated).

    Raises CaptureError if the file cannot be opened or is not a capture file.
    A truncated/corrupted file does NOT raise: the packets read so far are
    yielded, a warning is logged and iteration stops.
    """
    if not os.path.isfile(path):
        raise CaptureError(f"PCAP file not found: {path}")

    try:
        # RawPcapReader auto-switches to RawPcapNgReader when it sees a pcapng magic.
        reader = RawPcapReader(path)
    except (Scapy_Exception, OSError, EOFError) as exc:
        raise CaptureError(f"Cannot open capture file {path}: {exc}") from exc

    source = f"pcap:{os.path.basename(path)}"
    is_pcapng = isinstance(reader, RawPcapNgReader)
    index = 0
    try:
        # Iteration stops cleanly at EOF (including a half-written record header).
        for data, meta in reader:
            index += 1
            if is_pcapng:
                yield _from_pcapng(data, meta, source)
            else:
                yield _from_pcap(data, meta, reader.linktype, reader.nano, source)
    except (Scapy_Exception, OSError, ValueError, TypeError) as exc:
        # Corrupted record header, bad block... keep what we already yielded.
        logger.warning("Stopped reading %s after %d packets: %s", path, index, exc)
    finally:
        reader.close()


def _from_pcap(data: bytes, meta, linktype: int, nano: bool, source: str) -> RawPacket:
    """Convert a classic pcap record (sec, usec|nsec, wirelen, caplen)."""
    divisor = 1_000_000_000 if nano else 1_000_000
    if len(data) < meta.caplen:
        # The file ends in the middle of this record (truncated PCAP).
        logger.warning(
            "Truncated record in %s: expected %d bytes, got %d",
            source,
            meta.caplen,
            len(data),
        )
    return RawPacket(
        timestamp=meta.sec + meta.usec / divisor,
        data=data,
        linktype=linktype,
        wire_len=meta.wirelen,
        truncated=len(data) < meta.wirelen,
        source=source,
    )


def _from_pcapng(data: bytes, meta, source: str) -> RawPacket:
    """Convert a pcapng Enhanced Packet Block (64-bit ts split in tshigh/tslow)."""
    ticks = (meta.tshigh << 32) | meta.tslow
    return RawPacket(
        timestamp=ticks / meta.tsresol,
        data=data,
        linktype=meta.linktype,
        wire_len=meta.wirelen,
        truncated=meta.wirelen is not None and len(data) < meta.wirelen,
        source=source,
    )
