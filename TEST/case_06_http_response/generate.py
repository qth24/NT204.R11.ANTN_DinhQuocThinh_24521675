"""Generate input.pcap for case 06: HTTP responses (status line + headers)."""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT_IP, CLIENT_MAC = "192.168.1.10", "00:11:22:33:44:55"
SERVER_IP, SERVER_MAC = "93.184.216.34", "66:77:88:99:aa:bb"
BASE_TIME = 1759000500.0

HTML = b"<html><body><h1>Xin chao</h1></body></html>"
OK_200 = (
    b"HTTP/1.1 200 OK\r\n"
    b"Date: Sun, 28 Sep 2025 10:00:00 GMT\r\n"
    b"Server: nginx/1.24.0\r\n"
    b"Content-Type: text/html; charset=utf-8\r\n"
    b"Content-Length: " + str(len(HTML)).encode() + b"\r\n"
    b"Set-Cookie: session=abc123; HttpOnly\r\n"
    b"Set-Cookie: theme=dark\r\n"
    b"\r\n" + HTML
)
NOT_FOUND_404 = (
    b"HTTP/1.1 404 Not Found\r\n"
    b"Server: Apache/2.4.58\r\n"
    b"Content-Length: 0\r\n"
    b"\r\n"
)
REDIRECT_301 = (
    b"HTTP/1.0 301 Moved Permanently\r\n"
    b"Location: https://example.com/\r\n"
    b"\r\n"
)


def main() -> None:
    eth = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    ip = IP(src=SERVER_IP, dst=CLIENT_IP)
    packets = [
        eth / ip / TCP(sport=80, dport=51000, flags="PA", seq=900) / Raw(OK_200),
        eth / ip / TCP(sport=80, dport=51002, flags="PA", seq=500) / Raw(NOT_FOUND_404),
        eth / ip / TCP(sport=80, dport=51003, flags="PA", seq=700) / Raw(REDIRECT_301),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
