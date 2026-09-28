"""Generate input.pcap for case 01: TCP 3-way handshake (SYN / SYN-ACK / ACK)."""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

CLIENT = ("192.168.1.10", 51234, "00:11:22:33:44:55")
SERVER = ("192.168.1.20", 80, "66:77:88:99:aa:bb")
BASE_TIME = 1759000000.0


def main() -> None:
    c_ip, c_port, c_mac = CLIENT
    s_ip, s_port, s_mac = SERVER
    c2s = Ether(src=c_mac, dst=s_mac) / IP(src=c_ip, dst=s_ip)
    s2c = Ether(src=s_mac, dst=c_mac) / IP(src=s_ip, dst=c_ip)

    packets = [
        c2s / TCP(sport=c_port, dport=s_port, flags="S", seq=1000),
        s2c / TCP(sport=s_port, dport=c_port, flags="SA", seq=5000, ack=1001),
        c2s / TCP(sport=c_port, dport=s_port, flags="A", seq=1001, ack=5001),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
