"""Generate input.pcap for case 02: TCP segments carrying payload.

The service runs on port 9000 (no supported application protocol), so the
parser must extract the TCP layer and payload length without guessing HTTP,
DNS or SMTP.
"""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT = ("10.0.0.5", 50000, "00:11:22:33:44:55")
SERVER = ("10.0.0.8", 9000, "66:77:88:99:aa:bb")
BASE_TIME = 1759000100.0


def main() -> None:
    c_ip, c_port, c_mac = CLIENT
    s_ip, s_port, s_mac = SERVER
    c2s = Ether(src=c_mac, dst=s_mac) / IP(src=c_ip, dst=s_ip)
    s2c = Ether(src=s_mac, dst=c_mac) / IP(src=s_ip, dst=c_ip)

    text = b"Hello IDS, this is a plain text message\n"
    binary = bytes(range(256))  # binary data, not valid UTF-8
    packets = [
        c2s
        / TCP(sport=c_port, dport=s_port, flags="PA", seq=2001, ack=7001)
        / Raw(text),
        s2c
        / TCP(sport=s_port, dport=c_port, flags="A", seq=7001, ack=2001 + len(text)),
        s2c
        / TCP(sport=s_port, dport=c_port, flags="PA", seq=7001, ack=2001 + len(text))
        / Raw(binary),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
