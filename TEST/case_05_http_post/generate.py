"""Generate input.pcap for case 05: HTTP POST requests with a body.

1. Form login POST, body fully inside one segment.
2. JSON POST whose body is split over two TCP segments: the first carries the
   headers and part of the body, the second only the rest of the body.
"""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT_IP, CLIENT_MAC = "192.168.1.10", "00:11:22:33:44:55"
SERVER_IP, SERVER_MAC = "192.168.1.80", "66:77:88:99:aa:bb"
BASE_TIME = 1759000400.0

FORM_BODY = b"username=admin&password=P%40ssw0rd&remember=1"
JSON_BODY = b'{"device": "sensor-01", "temperature": 31.5, "note": "phong may B2"}'


def _post(uri: str, content_type: str, body: bytes) -> bytes:
    return (
        f"POST {uri} HTTP/1.1\r\n"
        f"Host: 192.168.1.80\r\n"
        f"User-Agent: python-requests/2.32\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
    ).encode() + body


def main() -> None:
    eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    ip = IP(src=CLIENT_IP, dst=SERVER_IP)

    login = _post("/login", "application/x-www-form-urlencoded", FORM_BODY)
    upload = _post("/api/v1/readings", "application/json", JSON_BODY)
    split_at = len(upload) - 30  # last 30 bytes of the body go in segment 2
    part1, part2 = upload[:split_at], upload[split_at:]

    packets = [
        eth / ip / TCP(sport=52000, dport=80, flags="PA", seq=1) / Raw(login),
        eth / ip / TCP(sport=52001, dport=80, flags="A", seq=1) / Raw(part1),
        eth
        / ip
        / TCP(sport=52001, dport=80, flags="PA", seq=1 + len(part1))
        / Raw(part2),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
