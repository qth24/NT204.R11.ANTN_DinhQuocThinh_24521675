"""Generate input.pcap for case 04: HTTP GET requests.

Packet 1 uses the standard port 80; packet 2 uses port 8081, which is not an
HTTP port, to show that detection is payload-based.
"""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT_IP, CLIENT_MAC = "192.168.1.10", "00:11:22:33:44:55"
SERVER_IP, SERVER_MAC = "93.184.216.34", "66:77:88:99:aa:bb"
BASE_TIME = 1759000300.0

GET_PORT_80 = (
    b"GET /index.html?lang=vi HTTP/1.1\r\n"
    b"Host: example.com\r\n"
    b"User-Agent: Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0\r\n"
    b"Accept: text/html\r\n"
    b"Connection: keep-alive\r\n"
    b"\r\n"
)
GET_PORT_8081 = (
    b"GET /api/status HTTP/1.1\r\n"
    b"Host: internal.local:8081\r\n"
    b"User-Agent: curl/8.5.0\r\n"
    b"\r\n"
)


def main() -> None:
    eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    ip = IP(src=CLIENT_IP, dst=SERVER_IP)
    packets = [
        eth
        / ip
        / TCP(sport=51000, dport=80, flags="PA", seq=100, ack=900)
        / Raw(GET_PORT_80),
        eth
        / ip
        / TCP(sport=51001, dport=8081, flags="PA", seq=300, ack=700)
        / Raw(GET_PORT_8081),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
