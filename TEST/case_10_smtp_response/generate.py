"""Generate input.pcap for case 10: SMTP server replies (status codes).

Greeting 220, multi-line EHLO reply, 250 with enhanced status, 354, pipelined
replies in one segment, 550 rejection, 421 temporary failure and 221 bye.
"""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT_IP, CLIENT_MAC = "192.168.1.10", "00:11:22:33:44:55"
SERVER_IP, SERVER_MAC = "192.168.1.25", "66:77:88:99:aa:bb"
BASE_TIME = 1759000900.0

REPLIES = [
    b"220 mail.uit.edu.vn ESMTP Postfix\r\n",
    (
        b"250-mail.uit.edu.vn\r\n"
        b"250-PIPELINING\r\n"
        b"250-SIZE 10240000\r\n"
        b"250-STARTTLS\r\n"
        b"250 AUTH PLAIN LOGIN\r\n"
    ),
    b"250 2.1.0 Ok\r\n",
    b"250 2.1.5 Ok\r\n250 2.1.5 Ok\r\n354 End data with <CR><LF>.<CR><LF>\r\n",
    b"550 5.1.1 <nobody@uit.edu.vn>: Recipient address rejected: User unknown\r\n",
    b"421 4.7.0 Too many connections, try again later\r\n",
    b"221 2.0.0 Bye\r\n",
]


def main() -> None:
    eth = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    ip = IP(src=SERVER_IP, dst=CLIENT_IP)
    packets = []
    seq = 1
    for i, reply in enumerate(REPLIES):
        pkt = eth / ip / TCP(sport=25, dport=53000, flags="PA", seq=seq) / Raw(reply)
        pkt.time = BASE_TIME + i * 0.01
        packets.append(pkt)
        seq += len(reply)
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
