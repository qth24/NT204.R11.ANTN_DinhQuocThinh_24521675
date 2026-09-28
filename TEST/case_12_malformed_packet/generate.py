"""Generate the inputs of case 12: malformed packets and a truncated PCAP.

input.pcap           : 14 malformed frames (one per error type, every layer)
                       followed by 1 valid HTTP GET to show that processing
                       continues after errors.
input_truncated.pcap : a valid 3-packet capture cut in the middle of the
                       last record (e.g. capture interrupted, disk full).

Frames are written as raw bytes (RawPcapWriter) so Scapy cannot "fix" them.
"""

import struct
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import RawPcapWriter

HERE = Path(__file__).parent
BASE_TIME = 1759001100.0

ETH = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
IP_HDR = IP(src="192.168.1.10", dst="192.168.1.20")


def _frame(pkt) -> bytearray:
    return bytearray(bytes(ETH / pkt))


def _set(frame: bytearray, offset: int, fmt: str, value: int) -> bytes:
    struct.pack_into(fmt, frame, offset, value)
    return bytes(frame)


# Offsets inside an Ethernet frame: IP header at 14, transport header at 34.
IP_OFF, L4_OFF = 14, 34


def malformed_frames() -> list[tuple[str, bytes]]:
    tcp = _frame(IP_HDR / TCP(sport=51000, dport=80, flags="S"))
    udp = _frame(IP_HDR / UDP(sport=51001, dport=9999) / Raw(b"abcdef"))

    # DNS query whose name is a compression pointer to itself (infinite loop)
    dns_loop = struct.pack("!HHHHHH", 0x3001, 0x0100, 1, 0, 0, 0)
    dns_loop += b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    # DNS response announcing 50 answers but containing none
    dns_counts = bytearray(bytes(DNS(id=0x3002, qr=1, qd=DNSQR(qname="uit.edu.vn"))))
    struct.pack_into("!H", dns_counts, 6, 50)

    return [
        ("empty frame (0 bytes)", b""),
        ("Ethernet header truncated (10 bytes)", bytes(tcp[:10])),
        ("IPv4 header truncated (12 of 20 bytes)", bytes(tcp[: IP_OFF + 12])),
        ("IP version = 5", _set(bytearray(tcp), IP_OFF, "!B", 0x55)),
        ("IPv4 IHL = 3 (12-byte header)", _set(bytearray(tcp), IP_OFF, "!B", 0x43)),
        (
            "IPv4 total length 1500 > captured",
            _set(bytearray(tcp), IP_OFF + 2, "!H", 1500),
        ),
        ("IPv4 total length 10 < header", _set(bytearray(tcp), IP_OFF + 2, "!H", 10)),
        (
            "TCP header truncated (10 of 20 bytes)",
            _set(bytearray(tcp[: L4_OFF + 10]), IP_OFF + 2, "!H", 30),
        ),
        ("TCP data offset = 3", _set(bytearray(tcp), L4_OFF + 12, "!B", 0x30)),
        ("UDP length = 4 (< 8)", _set(bytearray(udp), L4_OFF + 4, "!H", 4)),
        (
            "DNS compression pointer loop",
            bytes(_frame(IP_HDR / UDP(sport=51002, dport=53) / Raw(dns_loop))),
        ),
        (
            "DNS header claims 50 answers, has 0",
            bytes(_frame(IP_HDR / UDP(sport=53, dport=51003) / Raw(bytes(dns_counts)))),
        ),
        (
            "HTTP: broken header line, bad Content-Length, non-UTF-8 body",
            bytes(
                _frame(
                    IP_HDR
                    / TCP(sport=51004, dport=80, flags="PA")
                    / Raw(
                        b"POST /upload HTTP/1.1\r\n"
                        b"Host: example.com\r\n"
                        b"this line has no colon\r\n"
                        b"Content-Length: -5\r\n"
                        b"\r\n\xff\xfe\x00\x81\xc3"
                    )
                )
            ),
        ),
        (
            "SMTP: MAIL without FROM:<>, invalid reply code",
            bytes(
                _frame(
                    IP_HDR
                    / TCP(sport=51005, dport=25, flags="PA")
                    / Raw(b"MAIL thinh@uit.edu.vn\r\nHELO\r\n")
                )
            ),
        ),
    ]


def valid_frame() -> bytes:
    return bytes(
        _frame(
            IP_HDR
            / TCP(sport=51006, dport=80, flags="PA")
            / Raw(b"GET /still-working HTTP/1.1\r\nHost: example.com\r\n\r\n")
        )
    )


def _write(path: Path, frames: list[bytes]) -> None:
    writer = RawPcapWriter(str(path), linktype=1)
    writer.write_header(None)  # write_packet() does not write the file header
    for i, frame in enumerate(frames):
        ts = BASE_TIME + i * 0.001
        sec, usec = int(ts), round((ts - int(ts)) * 1_000_000)
        writer.write_packet(frame, sec=sec, usec=usec)
    writer.close()


def main() -> None:
    frames = [frame for _, frame in malformed_frames()] + [valid_frame()]
    _write(HERE / "input.pcap", frames)

    # Valid 3-packet capture, then cut 25 bytes from the end of the file.
    full = HERE / "input_truncated.pcap"
    _write(full, [valid_frame(), valid_frame(), valid_frame()])
    data = full.read_bytes()
    full.write_bytes(data[:-25])


if __name__ == "__main__":
    main()
