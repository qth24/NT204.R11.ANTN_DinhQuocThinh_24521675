"""Generate input.pcap for case 07: DNS queries over UDP.

Queries 1-3 go to the standard port 53. Query 4 goes to port 5300 (not a DNS
port) to show payload-based detection.
"""

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

CLIENT_IP, CLIENT_MAC = "192.168.1.10", "00:11:22:33:44:55"
RESOLVER_IP, RESOLVER_MAC = "8.8.8.8", "66:77:88:99:aa:bb"
BASE_TIME = 1759000600.0


def main() -> None:
    eth = Ether(src=CLIENT_MAC, dst=RESOLVER_MAC)
    ip = IP(src=CLIENT_IP, dst=RESOLVER_IP)
    queries = [
        (53001, 0x1A2B, "uit.edu.vn", "A", 53),
        (53002, 0x1A2C, "www.google.com", "AAAA", 53),
        (53003, 0x1A2D, "gmail.com", "MX", 53),
        (53004, 0x1A2E, "internal.corp", "TXT", 5300),
    ]
    packets = [
        eth
        / ip
        / UDP(sport=sport, dport=dport)
        / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype))
        for sport, qid, name, qtype, dport in queries
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
