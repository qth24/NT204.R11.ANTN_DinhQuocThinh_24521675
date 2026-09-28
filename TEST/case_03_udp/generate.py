"""Generate input.pcap for case 03: plain UDP datagrams (no application parser)."""

from pathlib import Path

from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT = ("172.16.0.3", 40001, "00:11:22:33:44:55")
SERVER = ("172.16.0.9", 9999, "66:77:88:99:aa:bb")
BASE_TIME = 1759000200.0


def main() -> None:
    c_ip, c_port, c_mac = CLIENT
    s_ip, s_port, s_mac = SERVER
    c2s = Ether(src=c_mac, dst=s_mac) / IP(src=c_ip, dst=s_ip)
    s2c = Ether(src=s_mac, dst=c_mac) / IP(src=s_ip, dst=c_ip)

    packets = [
        c2s / UDP(sport=c_port, dport=s_port) / Raw(b"PING seq=1"),
        s2c / UDP(sport=s_port, dport=c_port) / Raw(b"PONG seq=1"),
        c2s / UDP(sport=c_port, dport=s_port),  # empty datagram
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
