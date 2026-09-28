"""Generate input.pcap for case 08: DNS responses with answers.

1. www.uit.edu.vn -> CNAME + A (2 answers)
2. gmail.com MX -> 2 MX answers
3. nosuchdomain.invalid -> NXDOMAIN with an SOA record in the authority section
Messages are compressed with dns_compress() like a real server does, so
repeated names are encoded as compression pointers (0xC0..).
"""

from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR, DNSRRMX, DNSRRSOA, dns_compress
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

CLIENT_IP, CLIENT_MAC = "192.168.1.10", "00:11:22:33:44:55"
RESOLVER_IP, RESOLVER_MAC = "8.8.8.8", "66:77:88:99:aa:bb"
BASE_TIME = 1759000700.0


def main() -> None:
    eth = Ether(src=RESOLVER_MAC, dst=CLIENT_MAC)
    ip = IP(src=RESOLVER_IP, dst=CLIENT_IP)

    cname_a = DNS(
        id=0x2001,
        qr=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname="www.uit.edu.vn", qtype="A"),
        an=[
            DNSRR(rrname="www.uit.edu.vn", type="CNAME", ttl=3600, rdata="uit.edu.vn"),
            DNSRR(rrname="uit.edu.vn", type="A", ttl=300, rdata="118.69.123.140"),
        ],
    )
    mx = DNS(
        id=0x2002,
        qr=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname="gmail.com", qtype="MX"),
        an=[
            DNSRRMX(
                rrname="gmail.com",
                ttl=3600,
                preference=5,
                exchange="gmail-smtp-in.l.google.com",
            ),
            DNSRRMX(
                rrname="gmail.com",
                ttl=3600,
                preference=10,
                exchange="alt1.gmail-smtp-in.l.google.com",
            ),
        ],
    )
    nxdomain = DNS(
        id=0x2003,
        qr=1,
        rd=1,
        ra=1,
        rcode=3,
        qd=DNSQR(qname="nosuchdomain.invalid", qtype="A"),
        ns=DNSRRSOA(
            rrname="invalid",
            ttl=900,
            mname="a.root-servers.net",
            rname="nstld.verisign-grs.com",
            serial=2025092800,
            refresh=1800,
            retry=900,
            expire=604800,
            minimum=86400,
        ),
    )

    packets = [
        eth / ip / UDP(sport=53, dport=53001) / dns_compress(cname_a),
        eth / ip / UDP(sport=53, dport=53002) / dns_compress(mx),
        eth / ip / UDP(sport=53, dport=53003) / dns_compress(nxdomain),
    ]
    for i, pkt in enumerate(packets):
        pkt.time = BASE_TIME + i * 0.001
    wrpcap(str(Path(__file__).parent / "input.pcap"), packets)


if __name__ == "__main__":
    main()
