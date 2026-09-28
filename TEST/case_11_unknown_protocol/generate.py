"""Generate input.pcap for case 11: protocols the parser does not support.

Network layer not IPv4: ARP, IPv6, LLDP.
IPv4 but transport not TCP/UDP: ICMP echo, GRE.
TCP/UDP but application not HTTP/DNS/SMTP: SSH banner, NTP request.
"""

from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, GRE, Ether
from scapy.layers.ntp import NTP
from scapy.packet import Raw
from scapy.utils import wrpcap

A_IP, A_MAC = "192.168.1.10", "00:11:22:33:44:55"
B_IP, B_MAC = "192.168.1.20", "66:77:88:99:aa:bb"
BASE_TIME = 1759001000.0


def main() -> None:
    eth = Ether(src=A_MAC, dst=B_MAC)
    ip = IP(src=A_IP, dst=B_IP)
    packets = [
        Ether(src=A_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(psrc=A_IP, pdst=B_IP),
        eth / IPv6(src="fe80::1", dst="fe80::2") / UDP(sport=546, dport=547),
        Ether(src=A_MAC, dst="01:80:c2:00:00:0e", type=0x88CC) / Raw(b"\x02\x07"),
        eth / ip / ICMP(type=8, id=1, seq=1) / Raw(b"abcdefgh"),
        eth / ip / GRE() / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
        eth
        / ip
        / TCP(sport=22, dport=51000, flags="PA")
        / Raw(b"SSH-2.0-OpenSSH_9.6\r\n"),
        # fixed timestamps: NTP() fills orig/sent with the current time
        eth
        / ip
        / UDP(sport=51001, dport=123)
        / NTP(ref=0, orig=0, recv=0, sent=3968000000),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
