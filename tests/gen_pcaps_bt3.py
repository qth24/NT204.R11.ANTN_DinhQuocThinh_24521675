"""Generate the inputs of the BT3 test cases (TEST/BT3/case_XX_<name>/).

Writes, for every case, the rule file(s) (``*.rules``) and the input:
    * ``input_events.jsonl``  hand-made events (cases that only need a matcher
      to look at specific header/flags/payload values)
    * ``input.pcap``          built with Scapy (end-to-end cases 08, 13, 14)

Everything is deterministic: fixed addresses, ports and timestamps.

Usage (from the repository root):
    python tests/gen_pcaps_bt3.py            # all cases
    python tests/gen_pcaps_bt3.py 08 13      # only some cases
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.packet import Packet  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from tests.gen_pcaps_bt2 import BASE_TIME, TcpConn, http_message, udp  # noqa: E402

TEST_DIR = ROOT / "TEST" / "BT3"
NAMES = {
    "01": "rule_loader",
    "02": "invalid_rules",
    "03": "unsupported_rules",
    "04": "header_parse",
    "05": "direction",
    "06": "indexer",
    "07": "header_reject",
    "08": "flow_established",
    "09": "content_nocase",
    "10": "offset_depth",
    "11": "distance_within",
    "12": "flags_dsize",
    "13": "multi_match",
    "14": "detection_event",
}


def case_dir(case: str) -> Path:
    folder = TEST_DIR / f"case_{case}_{NAMES[case]}"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def write_rules(case: str, name: str, text: str) -> None:
    (case_dir(case) / name).write_text(text.strip() + "\n", encoding="utf-8")


def event(
    packet_id: int,
    src: tuple[str, int] = ("10.0.0.1", 4000),
    dst: tuple[str, int] = ("10.0.0.2", 80),
    payload: bytes = b"",
    flags: tuple[str, ...] = ("ACK",),
    proto: str = "TCP",
) -> dict:
    """A BT1-style event as the pipeline would read it from a JSONL file."""
    return {
        "packet_id": packet_id,
        "timestamp": BASE_TIME + packet_id,
        "src_ip": src[0],
        "dst_ip": dst[0],
        "protocol": proto,
        "src_port": src[1],
        "dst_port": dst[1],
        "tcp_flags": list(flags) if proto == "TCP" else [],
        "app_protocol": None,
        "app_data": {},
        "error": None,
        "ip_total_length": 40 + len(payload),
        "payload_length": len(payload),
        "payload_b64": base64.b64encode(payload).decode("ascii"),
    }


def save_events(case: str, events: list[dict]) -> None:
    text = "".join(json.dumps(e) + "\n" for e in events)
    (case_dir(case) / "input_events.jsonl").write_text(text, encoding="utf-8")


def save_pcap(case: str, timeline: list[tuple[float, Packet]]) -> None:
    packets = []
    for offset, packet in timeline:
        packet.time = BASE_TIME + offset
        packets.append(packet)
    wrpcap(str(case_dir(case) / "input.pcap"), packets)


# --- case 01 - 03: loader, parser, validator ----------------------------------


def c01() -> None:
    write_rules(
        "01",
        "case.rules",
        r"""
# Case 01 - rule loader: comments, blank lines, a commented-out rule,
# a rule split over two lines and one broken rule.

alert tcp any any -> any 80 (msg:"A web GET"; content:"GET"; sid:101;)
#alert tcp any any -> any 81 (msg:"commented out, must stay off"; sid:102;)

alert udp any any -> any 53 (msg:"B dns"; content:"|07|example"; sid:103;)
alert tcp any any -> any 25 \
    (msg:"C smtp, written on two lines"; content:"MAIL"; nocase; sid:104;)
alert tcp any any -> any 80 (msg:"D no sid"; content:"x";)
""",
    )
    save_events("01", [event(1, payload=b"GET / HTTP/1.1\r\n\r\n")])


def c02() -> None:
    write_rules(
        "02",
        "invalid.rules",
        r"""
alert tcp any any -> any 80 (msg:"missing sid"; content:"a";)
alert tcp any any -> any 80 (msg:"minimal rule"; sid:202;)
alert tcp any any -> any 80 (content:"a"; sid:203;)
alert tcp any any -> any 80:20 (msg:"bad range"; sid:204;)
alert tcp any any <- any 80 (msg:"bad direction"; sid:205;)
alert tcp any any -> any 80 (msg:"distance first"; distance:2; sid:206;)
alert tcp any any -> any 80 (msg:"unterminated; sid:207;)
alert tcp any any -> 10.0.0.0/33 80 (msg:"bad cidr"; sid:208;)
alert tcp any any -> any 80 (msg:"valid rule"; content:"GET"; sid:209;)
alert tcp any any -> any 80 (msg:"same sid again"; content:"POST"; sid:209;)
alert tcp any any -> any 80 (msg:"depth too small"; content:"GET /"; depth:3; sid:211;)
alert tcp any any -> any 80 (msg:"bad hex"; content:"|4G|"; sid:212;)
alert tcp any any -> any 80 (msg:"flow conflict"; flow:established,not_established; sid:213;)
alert tcp any any -> any 70000 (msg:"bad port"; sid:214;)
alert tcp any any -> any 80 (msg:"offset+distance"; content:"a"; offset:1; distance:1; sid:215;)
""",
    )
    save_events("02", [event(1, payload=b"GET / HTTP/1.1\r\n\r\n")])


def c03() -> None:
    write_rules(
        "03",
        "unsupported.rules",
        r"""
alert tcp any any -> any 80 (msg:"pcre"; pcre:"/abc/i"; sid:301;)
alert tcp any any -> any 80 (msg:"byte_test"; byte_test:1,>,5,0; sid:302;)
alert tcp any any -> any 80 (msg:"http_uri"; content:"/admin"; http_uri; sid:303;)
drop tcp any any -> any 80 (msg:"drop action"; sid:304;)
alert icmp any any -> any any (msg:"icmp"; sid:305;)
alert tcp !10.0.0.0/8 any -> any 80 (msg:"negated ip"; sid:306;)
alert tcp any any -> any [80,443] (msg:"port list"; sid:307;)
alert tcp $HOME_NET any -> any 80 (msg:"variable"; sid:308;)
alert tcp any any -> any 80 (msg:"flowbits"; flowbits:set,x; sid:309;)
alert tcp any any -> any 80 (msg:"harmless keywords"; content:"GET"; reference:cve,2020-0001; metadata:service http; gid:1; sid:310;)
""",
    )
    save_events("03", [event(1, payload=b"GET /admin HTTP/1.1\r\n\r\n")])


# --- case 04 - 07: header, direction, index -----------------------------------


def c04() -> None:
    write_rules(
        "04",
        "header.rules",
        r"""
alert tcp any any -> any any (msg:"h1 any"; sid:401;)
alert tcp 192.168.1.10 any -> 10.0.0.5 80 (msg:"h2 single ip, single port"; sid:402;)
alert tcp 10.0.0.0/8 1024: -> 192.168.0.0/16 1:1024 (msg:"h3 cidr and ranges"; sid:403;)
alert tcp any :1023 <> any 8080 (msg:"h4 open range, bidirectional"; sid:404;)
alert tcp 10.1.2.3/8 any -> any any (msg:"h5 host bits in cidr"; sid:405;)
alert tcp any any -> any 80 (msg:"full rule; with semicolon"; content:"a\;b|3a 20|c"; nocase; offset:2; depth:10; flow:to_server,established; flags:+SA,CE; dsize:4<>8; classtype:web-attack; priority:2; sid:406; rev:3;)
""",
    )
    save_events("04", [event(1)])


def c05() -> None:
    write_rules(
        "05",
        "direction.rules",
        r"""
alert tcp 10.0.0.1 any -> 10.0.0.2 80 (msg:"one way"; sid:501;)
alert tcp 10.0.0.1 any <> 10.0.0.2 80 (msg:"both ways"; sid:502;)
""",
    )
    save_events(
        "05",
        [
            event(1),  # 10.0.0.1:4000 -> 10.0.0.2:80
            event(2, src=("10.0.0.2", 80), dst=("10.0.0.1", 4000)),  # reversed
            event(3, dst=("10.0.0.3", 80)),  # other destination
        ],
    )


def c06() -> None:
    write_rules(
        "06",
        "index.rules",
        r"""
alert tcp any any -> any 80 (msg:"tcp 80"; sid:601;)
alert tcp any any -> any 1:1024 (msg:"tcp 1-1024"; sid:602;)
alert tcp any any -> any any (msg:"tcp any"; sid:603;)
alert udp any any -> any 53 (msg:"udp 53"; sid:604;)
alert udp any any -> any any (msg:"udp any"; sid:605;)
alert tcp any any <> any 8080 (msg:"tcp 8080 both ways"; sid:606;)
alert tcp 10.0.0.0/8 any -> any 443 (msg:"tcp 443 from 10/8"; sid:607;)
""",
    )
    events = [
        event(1, dst=("10.0.0.2", 80)),
        event(2, dst=("10.0.0.2", 443)),
        event(3, dst=("10.0.0.2", 8080)),
        event(4, src=("10.0.0.2", 8080), dst=("10.0.0.1", 5000)),
        event(5, dst=("10.0.0.2", 53), proto="UDP"),
        event(6, dst=("10.0.0.2", 9999), proto="UDP"),
    ]
    no_ports = event(7)
    no_ports["src_port"] = no_ports["dst_port"] = None
    save_events("06", [*events, no_ports])


def c07() -> None:
    write_rules(
        "07",
        "header_reject.rules",
        r"""
alert tcp any any -> any 80 (msg:"header ok, then content"; content:"GET"; sid:701;)
alert tcp any any -> any 443 (msg:"other port (index drops it)"; content:"GET"; sid:702;)
alert tcp 10.9.9.9 any -> any 80 (msg:"other source ip (header rejects it)"; content:"GET"; sid:703;)
alert udp any any -> any 80 (msg:"other protocol"; content:"GET"; sid:704;)
""",
    )
    save_events(
        "07",
        [
            event(1, payload=b"GET / HTTP/1.1\r\n\r\n"),
            event(2, payload=b"hello"),
        ],
    )


# --- case 08: flow, end-to-end ------------------------------------------------


def c08() -> None:
    write_rules(
        "08",
        "flow.rules",
        r"""
alert tcp any any -> any 80 (msg:"to_server established"; flow:to_server,established; sid:801;)
alert tcp any any -> any 80 (msg:"to_server not_established"; flow:to_server,not_established; sid:802;)
alert tcp any any <> any 80 (msg:"to_client established"; flow:to_client,established; sid:803;)
alert tcp any any -> any 80 (msg:"GET to_server established"; flow:to_server,established; content:"GET"; sid:804;)
""",
    )
    conn = TcpConn(("192.168.1.10", 51000), ("192.168.1.20", 80))
    request = http_message("GET /index.html HTTP/1.1", {"Host": "example.com"})
    response = http_message(
        "HTTP/1.1 200 OK", {"Content-Length": "9"}, b"GET reply"
    )  # also contains "GET", but travels to the client
    save_pcap(
        "08",
        [
            (0.00, conn.pkt(True, "S")),
            (0.01, conn.pkt(False, "SA")),
            (0.02, conn.pkt(True, "A")),
            (0.03, conn.pkt(True, "PA", request)),
            (0.04, conn.pkt(False, "PA", response)),
            (0.05, conn.pkt(True, "A")),
        ],
    )


# --- case 09 - 12: content, flags, dsize --------------------------------------


def c09() -> None:
    write_rules(
        "09",
        "nocase.rules",
        r"""
alert tcp any any -> any 80 (msg:"case sensitive"; content:"GET /"; sid:901;)
alert tcp any any -> any 80 (msg:"nocase"; content:"get /"; nocase; sid:902;)
alert tcp any any -> any 80 (msg:"hex GET"; content:"|47 45 54|"; sid:903;)
alert tcp any any -> any 80 (msg:"nocase is ASCII only"; content:"gét"; nocase; sid:904;)
""",
    )
    save_events(
        "09",
        [
            event(1, payload=b"GET /index.html"),
            event(2, payload=b"get /index.html"),
            event(3, payload="GÉT /".encode()),  # É (C3 89) is not folded to é
            event(4, payload="GéT /".encode()),  # only the ASCII letters differ
        ],
    )


def c10() -> None:
    write_rules(
        "10",
        "offset_depth.rules",
        r"""
alert tcp any any -> any 80 (msg:"EF at 4, window [4,6)"; content:"EF"; offset:4; depth:2; sid:1001;)
alert tcp any any -> any 80 (msg:"EF, offset 5 is too late"; content:"EF"; offset:5; depth:5; sid:1002;)
alert tcp any any -> any 80 (msg:"EF, window [3,6) ends on the pattern"; content:"EF"; offset:3; depth:3; sid:1003;)
alert tcp any any -> any 80 (msg:"EF, window [3,5) is one byte short"; content:"EF"; offset:3; depth:2; sid:1004;)
alert tcp any any -> any 80 (msg:"IJ at the very end"; content:"IJ"; offset:8; sid:1005;)
alert tcp any any -> any 80 (msg:"IJ, offset 9 leaves one byte"; content:"IJ"; offset:9; sid:1006;)
alert tcp any any -> any 80 (msg:"AB, depth 2"; content:"AB"; depth:2; sid:1007;)
alert tcp any any -> any 80 (msg:"BC, depth 2 too short"; content:"BC"; depth:2; sid:1008;)
alert tcp any any -> any 80 (msg:"BC, depth 3"; content:"BC"; depth:3; sid:1009;)
""",
    )
    save_events("10", [event(1, payload=b"ABCDEFGHIJ")])


def c11() -> None:
    write_rules(
        "11",
        "distance_within.rules",
        r"""
alert tcp any any -> any 80 (msg:"admin right after user="; content:"user="; content:"admin"; distance:0; within:5; sid:1101;)
alert tcp any any -> any 80 (msg:"pass not within 5"; content:"user="; content:"pass"; distance:0; within:5; sid:1102;)
alert tcp any any -> any 80 (msg:"pass within 15"; content:"user="; content:"pass"; distance:0; within:15; sid:1103;)
alert tcp any any -> any 80 (msg:"pass= at distance 6"; content:"user="; content:"pass="; distance:6; within:5; sid:1104;)
alert tcp any any -> any 80 (msg:"pass= at distance 7 misses"; content:"user="; content:"pass="; distance:7; within:5; sid:1105;)
alert tcp any any -> any 80 (msg:"negative distance"; content:"admin"; content:"in&"; distance:-2; within:3; sid:1106;)
alert tcp any any -> any 80 (msg:"first AB fails, second AB works"; content:"AB"; content:"XY"; distance:1; within:2; sid:1107;)
alert tcp any any -> any 80 (msg:"no AB leaves XY in reach"; content:"AB"; content:"XY"; distance:0; within:2; sid:1108;)
""",
    )
    save_events(
        "11",
        [
            event(1, payload=b"user=admin&pass=1234"),
            event(2, payload=b"AB-AB-XY"),
        ],
    )


def c12() -> None:
    write_rules(
        "12",
        "flags_dsize.rules",
        r"""
alert tcp any any -> any 80 (msg:"flags S exact"; flags:S; sid:1201;)
alert tcp any any -> any 80 (msg:"flags +SA"; flags:+SA; sid:1202;)
alert tcp any any -> any 80 (msg:"flags *FR any"; flags:*FR; sid:1203;)
alert tcp any any -> any 80 (msg:"flags !S none"; flags:!S; sid:1204;)
alert tcp any any -> any 80 (msg:"flags A, mask P"; flags:A,P; sid:1205;)
alert tcp any any -> any 80 (msg:"flags 0 (null)"; flags:0; sid:1206;)
alert tcp any any -> any 80 (msg:"dsize 0"; dsize:0; sid:1207;)
alert tcp any any -> any 80 (msg:"dsize >10"; dsize:>10; sid:1208;)
alert tcp any any -> any 80 (msg:"dsize 5<>8"; dsize:5<>8; sid:1209;)
alert tcp any any -> any 80 (msg:"pure ACK"; flags:A; dsize:0; sid:1210;)
""",
    )
    save_events(
        "12",
        [
            event(1, flags=("SYN",)),
            event(2, flags=("SYN", "ACK")),
            event(3, flags=("ACK",)),  # pure ACK, dsize 0
            event(4, flags=("PSH", "ACK"), payload=b"hello world!"),  # 12 bytes
            event(5, flags=("FIN", "ACK")),
            event(6, flags=()),  # null packet
            event(7, proto="UDP", payload=b"12345"),
            event(8, flags=("PSH", "ACK"), payload=b"12345678"),  # 8 bytes
        ],
    )


# --- case 13, 14: end-to-end ----------------------------------------------------

_HTTP_ATTACK = http_message(
    "GET /a/../b?q=1+UNION+SELECT+x HTTP/1.1", {"Host": "victim.example"}
)


def c13() -> None:
    write_rules(
        "13",
        "a_web.rules",
        r"""
alert tcp any any -> any 80 (msg:"GET request"; flow:to_server,established; content:"GET "; depth:4; sid:1301;)
alert tcp any any -> any 80 (msg:"path traversal"; flow:to_server,established; content:"../"; sid:1307;)
alert tcp any any -> any 80 (msg:"POST request"; flow:to_server,established; content:"POST "; depth:5; sid:1305;)
""",
    )
    write_rules(
        "13",
        "b_attack.rules",
        r"""
alert tcp any any -> any 80 (msg:"union select"; content:"union"; nocase; content:"select"; nocase; distance:1; within:10; sid:1303;)
alert tcp any any -> any any (msg:"any tcp payload"; dsize:>0; sid:1304;)
""",
    )
    conn = TcpConn(("192.168.1.10", 51100), ("192.168.1.20", 80))
    save_pcap(
        "13",
        [
            (0.00, conn.pkt(True, "S")),
            (0.01, conn.pkt(False, "SA")),
            (0.02, conn.pkt(True, "A")),
            (0.03, conn.pkt(True, "PA", _HTTP_ATTACK)),
        ],
    )


def c14() -> None:
    write_rules(
        "14",
        "detection.rules",
        r"""
alert tcp any any -> any 80 (msg:"WEB traversal in GET"; flow:to_server,established; content:"GET "; depth:4; content:"../"; distance:0; classtype:web-application-attack; priority:1; sid:1401; rev:2;)
alert udp any any -> any 53 (msg:"DNS query example.com"; content:"|07|example|03|com|00|"; nocase; classtype:misc-activity; sid:1402;)
""",
    )
    conn = TcpConn(("192.168.1.10", 51200), ("192.168.1.20", 80))
    request = http_message("GET /a/../etc/passwd HTTP/1.1", {"Host": "victim.example"})
    query = DNS(rd=1, id=0x1234, qd=DNSQR(qname="example.com"))
    save_pcap(
        "14",
        [
            (0.00, conn.pkt(True, "S")),
            (0.01, conn.pkt(False, "SA")),
            (0.02, conn.pkt(True, "A")),
            (0.03, conn.pkt(True, "PA", request)),
            (0.10, udp(("192.168.1.10", 53000), ("192.168.1.1", 53), query)),
        ],
    )


CASES = {n: globals()[f"c{n}"] for n in NAMES}


def main(argv: list[str]) -> int:
    wanted = argv or list(CASES)
    for case in wanted:
        CASES[case.zfill(2)]()
        print(f"case {case}: {case_dir(case.zfill(2)).name}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
