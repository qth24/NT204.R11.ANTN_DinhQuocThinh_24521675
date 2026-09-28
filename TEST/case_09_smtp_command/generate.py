"""Generate input.pcap for case 09: SMTP client commands.

A client session to port 25: HELO, EHLO, AUTH, MAIL FROM, RCPT TO, a
pipelined segment (RCPT TO x2 + DATA), the message content and QUIT.
"""

from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

CLIENT_IP, CLIENT_MAC = "192.168.1.10", "00:11:22:33:44:55"
SERVER_IP, SERVER_MAC = "192.168.1.25", "66:77:88:99:aa:bb"
BASE_TIME = 1759000800.0

COMMANDS = [
    b"HELO client.uit.local\r\n",
    b"EHLO client.uit.local\r\n",
    b"AUTH PLAIN AHRoaW5oAHNlY3JldDEyMw==\r\n",
    b"MAIL FROM:<thinh@uit.edu.vn> SIZE=512\r\n",
    b"RCPT TO:<giangvien@uit.edu.vn>\r\n",
    b"RCPT TO:<ta1@uit.edu.vn>\r\nRCPT TO:<ta2@uit.edu.vn>\r\nDATA\r\n",
    (
        b"From: Thinh <thinh@uit.edu.vn>\r\n"
        b"To: giangvien@uit.edu.vn\r\n"
        b"Subject: Nop bai tap 1 IDS\r\n"
        b"\r\n"
        b"Em gui thay bai tap 1.\r\n"
        b".\r\n"
    ),
    b"QUIT\r\n",
]


def main() -> None:
    eth = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    ip = IP(src=CLIENT_IP, dst=SERVER_IP)
    packets = []
    seq = 1
    for i, command in enumerate(COMMANDS):
        pkt = eth / ip / TCP(sport=53000, dport=25, flags="PA", seq=seq) / Raw(command)
        pkt.time = BASE_TIME + i * 0.01
        packets.append(pkt)
        seq += len(command)
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
