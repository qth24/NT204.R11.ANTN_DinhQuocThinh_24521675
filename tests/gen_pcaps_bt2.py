"""Generate the inputs of the BT2 test cases (TEST/bt2_TXX_<name>/).

PCAPs are built with Scapy; T05, T06 and T14 use hand-written event JSONL
(``input_events.jsonl``) because they test the Decoder/Preprocessor on
events that BT1 would never produce (lowercase protocol, missing fields...).

Everything is deterministic: fixed MAC/IP/ports, fixed timestamps (no
sleep: T12 simply uses timestamps further apart than the idle timeout), so
running this script again gives byte-identical files.

Usage (from the repository root):
    python tests/gen_pcaps_bt2.py            # all cases
    python tests/gen_pcaps_bt2.py T07 T12    # only some cases
"""

from __future__ import annotations

import base64
import json
import sys
from collections.abc import Callable
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Packet, Raw
from scapy.utils import wrpcap

TEST_DIR = Path(__file__).resolve().parent.parent / "TEST"
CLIENT_MAC, SERVER_MAC = "00:11:22:33:44:55", "66:77:88:99:aa:bb"
BASE_TIME = 1759100000.0


class TcpConn:
    """Builds the packets of one TCP connection with consistent seq/ack."""

    def __init__(
        self,
        client: tuple[str, int],
        server: tuple[str, int],
        client_isn: int = 1000,
        server_isn: int = 5000,
    ) -> None:
        self.client, self.server = client, server
        self.seq = {True: client_isn, False: server_isn}  # True = client side

    def pkt(self, from_client: bool, flags: str, payload: bytes = b"") -> Packet:
        src, dst = (
            (self.client, self.server) if from_client else (self.server, self.client)
        )
        smac, dmac = (
            (CLIENT_MAC, SERVER_MAC) if from_client else (SERVER_MAC, CLIENT_MAC)
        )
        ack = self.seq[not from_client] if "A" in flags else 0
        packet = (
            Ether(src=smac, dst=dmac)
            / IP(src=src[0], dst=dst[0])
            / TCP(
                sport=src[1],
                dport=dst[1],
                flags=flags,
                seq=self.seq[from_client],
                ack=ack,
            )
        )
        if payload:
            packet = packet / Raw(payload)
        # SYN and FIN consume one sequence number, data consumes its length
        self.seq[from_client] += len(payload) + ("S" in flags) + ("F" in flags)
        return packet


def udp(src: tuple[str, int], dst: tuple[str, int], payload: Packet | bytes) -> Packet:
    return (
        Ether(src=CLIENT_MAC, dst=SERVER_MAC)
        / IP(src=src[0], dst=dst[0])
        / UDP(sport=src[1], dport=dst[1])
        / (payload if isinstance(payload, Packet) else Raw(payload))
    )


def http_message(start_line: str, headers: dict[str, str], body: bytes = b"") -> bytes:
    head = start_line + "\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return head.encode("latin-1") + b"\r\n" + body


def save_pcap(case: str, timeline: list[tuple[float, Packet]]) -> None:
    packets = []
    for offset, packet in timeline:
        packet.time = BASE_TIME + offset
        packets.append(packet)
    folder = _case_dir(case)
    wrpcap(str(folder / "input.pcap"), packets)


def save_events(case: str, lines: list[dict | str]) -> None:
    """dict -> JSON line; str -> written verbatim (to test broken lines)."""
    text = "".join(
        (json.dumps(line, ensure_ascii=False) if isinstance(line, dict) else line)
        + "\n"
        for line in lines
    )
    (_case_dir(case) / "input_events.jsonl").write_text(text, encoding="utf-8")


def _case_dir(case: str) -> Path:
    matches = list(TEST_DIR.glob(f"bt2_{case}_*"))
    folder = matches[0] if matches else TEST_DIR / f"bt2_{case}_{CASE_NAMES[case]}"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


# --- T01 - T04: Decoder -------------------------------------------------------


def t01_http_url_decode() -> None:
    server = ("93.184.216.34", 80)
    requests = [
        "GET /search%20page/a+b?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E&lang=vi+VN&empty= HTTP/1.1",
        "GET /products?id=1%27%20OR%201%3D1--&sort=price HTTP/1.1",
        "GET /%252e%252e/%252e%252e/etc/passwd?f=%2527 HTTP/1.1",
        "GET /files/report%2Bfinal%20v2.pdf HTTP/1.1",
        "GET http://example.com/a%20b?x=1 HTTP/1.1",
    ]
    timeline = []
    for i, line in enumerate(requests):
        conn = TcpConn(("192.168.1.10", 52000 + i), server)
        timeline.append(
            (
                i * 0.01,
                conn.pkt(True, "PA", http_message(line, {"Host": "example.com"})),
            )
        )
    form = b"username=admin%27--&password=P%40ss+word%21"
    conn = TcpConn(("192.168.1.10", 52010), server)
    timeline.append(
        (
            0.1,
            conn.pkt(
                True,
                "PA",
                http_message(
                    "POST /login HTTP/1.1",
                    {
                        "Host": "example.com",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Content-Length": str(len(form)),
                    },
                    form,
                ),
            ),
        )
    )
    save_pcap("T01", timeline)


def t02_html_entity() -> None:
    server, client = ("93.184.216.34", 80), ("192.168.1.10", 52100)
    bodies = [
        (
            "text/html; charset=utf-8",
            b"<p>Comment: &lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;</p>",
        ),
        ("text/plain", b"Tom &amp; Jerry &copy; 2025 &#x1F600; &#8364;"),
        ("text/html", b"&amp;lt;script&amp;gt;double&amp;lt;/script&amp;gt;"),
        ("text/html", b"broken: &notanentity; &#99999999; &#xZZ; & alone"),
        ("application/json", b'{"msg": "&lt;b&gt; stays encoded in JSON"}'),
        ("image/png", b"\x89PNG\r\n\x1a\n&lt;not text&gt;\x00\xff"),
    ]
    timeline = []
    for i, (ctype, body) in enumerate(bodies):
        conn = TcpConn((client[0], client[1] + i), server)
        message = http_message(
            "HTTP/1.1 200 OK",
            {"Content-Type": ctype, "Content-Length": str(len(body))},
            body,
        )
        timeline.append((i * 0.01, conn.pkt(False, "PA", message)))
    form = b"comment=%26lt%3Bimg+src%3Dx+onerror%3Dalert(1)%26gt%3B&name=Th%E1%BB%8Bnh"
    conn = TcpConn((client[0], client[1] + 10), server)
    message = http_message(
        "POST /comment HTTP/1.1",
        {
            "Host": "example.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(form)),
        },
        form,
    )
    timeline.append((0.1, conn.pkt(True, "PA", message)))
    save_pcap("T02", timeline)


def _smtp_data(headers: str, body: bytes) -> bytes:
    return headers.replace("\n", "\r\n").encode() + b"\r\n" + body + b"\r\n.\r\n"


def t03_smtp_mime() -> None:
    server = ("192.168.1.25", 25)
    text = "Chào thầy, em gửi bài tập 2 IDS."
    b64_body = base64.b64encode(text.encode())
    b64_wrapped = b64_body[:20] + b"\r\n" + b64_body[20:]
    attachment = base64.b64encode(b"%PDF-1.4\n% fake pdf\n").rstrip(
        b"="
    )  # padding removed
    messages = [
        _smtp_data(
            "From: thinh@uit.edu.vn\nTo: gv@uit.edu.vn\nSubject: Base64\n"
            "MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n"
            "Content-Transfer-Encoding: base64\n",
            b64_wrapped,
        ),
        _smtp_data(
            "From: thinh@uit.edu.vn\nSubject: QP\nMIME-Version: 1.0\n"
            "Content-Type: text/plain; charset=utf-8\n"
            "Content-Transfer-Encoding: quoted-printable\n",
            b"Ch=C3=A0o th=E1=BA=A7y, 1 + 1 =3D 2 v=C3=A0 d=C3=B2ng n=C3=A0y r=E1=BA=A5t =\r\nd=C3=A0i.",
        ),
        _smtp_data(
            "From: thinh@uit.edu.vn\nSubject: Multipart\nMIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="SEP"\n',
            b"--SEP\r\nContent-Type: text/plain; charset=utf-8\r\n"
            b"Content-Transfer-Encoding: quoted-printable\r\n\r\nB=C3=A0i n=E1=BB=99p k=C3=A8m file.\r\n"
            b"--SEP\r\nContent-Type: application/pdf; name=bt2.pdf\r\n"
            b"Content-Transfer-Encoding: base64\r\n\r\n" + attachment + b"\r\n--SEP--",
        ),
        _smtp_data(
            "From: x@uit.edu.vn\nSubject: Broken\nContent-Type: text/plain\n"
            "Content-Transfer-Encoding: base64\n",
            b"!!!this is not base64!!!",
        ),
        _smtp_data(
            "From: x@uit.edu.vn\nSubject: Plain 7bit\n",
            b"Hello, no transfer encoding here.",
        ),
    ]
    timeline = []
    for i, message in enumerate(messages):
        conn = TcpConn(("192.168.1.10", 53000 + i), server)
        timeline.append((i * 0.01, conn.pkt(True, "PA", message)))
    save_pcap("T03", timeline)


def t04_invalid_bytes() -> None:
    server, client = ("192.168.1.80", 80), ("192.168.1.10", 54000)

    def response(ctype: str, body: bytes) -> bytes:
        return http_message(
            "HTTP/1.1 200 OK",
            {"Content-Type": ctype, "Content-Length": str(len(body))},
            body,
        )

    form = b"name=Th\xe1\xbb\x8bnh&city=\xff\xfeHCM"
    payloads = [
        (
            False,
            response("text/plain", b"Gi\xe1 tr\xff\xfe kh\xf4ng h\xe1\xbb\xa3p l\xe1"),
        ),
        (
            False,
            response(
                "text/html; charset=iso-8859-1", "<p>Café crème</p>".encode("latin-1")
            ),
        ),
        (
            True,
            http_message("GET /caf%E9?name=%FF%FE HTTP/1.1", {"Host": "example.com"}),
        ),
        (
            True,
            http_message(
                "POST /profile HTTP/1.1",
                {
                    "Host": "example.com",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": str(len(form)),
                },
                form,
            ),
        ),
        (
            False,
            response(
                "text/plain; charset=no-such-charset", b"\x81\x82 unknown charset"
            ),
        ),
    ]
    timeline = []
    for i, (from_client, payload) in enumerate(payloads):
        conn = TcpConn((client[0], client[1] + i), server)
        timeline.append((i * 0.01, conn.pkt(from_client, "PA", payload)))
    smtp = TcpConn(("192.168.1.10", 54100), ("192.168.1.25", 25))
    latin_b64 = base64.b64encode("café".encode("latin-1"))
    timeline.append(
        (
            0.1,
            smtp.pkt(
                True,
                "PA",
                _smtp_data(
                    "From: x@uit.edu.vn\nContent-Type: text/plain; charset=utf-8\n"
                    "Content-Transfer-Encoding: base64\n",
                    latin_b64,
                ),
            ),
        )
    )
    ok = TcpConn((client[0], client[1] + 50), server)
    timeline.append(
        (
            0.2,
            ok.pkt(
                True,
                "PA",
                http_message("GET /still-ok%21 HTTP/1.1", {"Host": "example.com"}),
            ),
        )
    )
    save_pcap("T04", timeline)


# --- T05, T06, T14: Preprocessor (event JSONL) ----------------------------------


def _base_event(packet_id: int, **fields) -> dict:
    event = {
        "packet_id": packet_id,
        "timestamp": BASE_TIME + packet_id,
        "src_ip": "192.168.1.10",
        "dst_ip": "93.184.216.34",
        "protocol": "TCP",
        "src_port": 51000 + packet_id,
        "dst_port": 80,
        "tcp_flags": ["PSH", "ACK"],
        "app_protocol": None,
        "app_data": {},
        "error": None,
        "ip_total_length": 100,
        "payload_length": 60,
    }
    event.update(fields)
    return event


def t05_normalization() -> None:
    http = {
        "type": "request",
        "method": "GET",
        "uri": "/a/./b/../../..//admin//panel%2F..%2Fusers?Sort=DESC",
        "version": "HTTP/1.1",
        "host": "WWW.Example.COM:8080",
        "headers": {
            "HOST": "WWW.Example.COM:8080",
            "uSeR-AgEnT": " curl/8.5 ",
            "Content-TYPE": "text/plain",
        },
    }
    save_events(
        "T05",
        [
            _base_event(1, protocol="tcp", app_protocol="http", app_data=http),
            _base_event(
                2,
                protocol="Tcp",
                app_protocol="HTTP",
                app_data={**http, "host": "www.example.com."},
            ),
            _base_event(
                3,
                protocol="udp",
                app_protocol="dns",
                dst_port=53,
                src_port=5353,
                tcp_flags=[],
                app_data={
                    "type": "query",
                    "questions": [{"name": "WWW.UIT.EDU.VN.", "type": "A"}],
                },
            ),
            _base_event(
                4,
                protocol="UDP",
                app_protocol="Dns",
                dst_port=53,
                src_port=5354,
                tcp_flags=[],
                app_data={
                    "type": "query",
                    "questions": [{"name": "Bücher.DE", "type": "A"}],
                },
            ),
            _base_event(5, src_ip=" 192.168.001.010 ", dst_ip="2001:DB8:0:0::1"),
        ],
    )


def t06_missing_field() -> None:
    save_events(
        "T06",
        [
            # only the core fields
            {
                "packet_id": 1,
                "timestamp": BASE_TIME + 1,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "UDP",
            },
            # TCP without ports / flags / app fields
            {
                "packet_id": 2,
                "timestamp": BASE_TIME + 2,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "protocol": "TCP",
            },
            # HTTP whose app_data lacks uri, host, headers, body
            _base_event(
                3, app_protocol="HTTP", app_data={"type": "request", "method": "GET"}
            ),
            # HTTP with app_data explicitly null
            _base_event(4, app_protocol="HTTP", app_data=None),
            # DNS without questions
            _base_event(
                5,
                protocol="UDP",
                dst_port=53,
                tcp_flags=[],
                app_protocol="DNS",
                app_data={"type": "query"},
            ),
            # SMTP data without preview
            _base_event(6, dst_port=25, app_protocol="SMTP", app_data={"type": "data"}),
            # complete event, for comparison
            _base_event(
                7,
                app_protocol="HTTP",
                app_data={
                    "type": "request",
                    "method": "GET",
                    "uri": "/ok",
                    "host": "a.com",
                    "headers": {"Host": "a.com"},
                },
            ),
        ],
    )


def t14_malformed_event() -> None:
    save_events(
        "T14",
        [
            "{this is not json",
            "[1, 2, 3]",
            '"just a string"',
            {"timestamp": BASE_TIME, "src_ip": "10.0.0.1"},  # most core fields missing
            _base_event(5, src_ip="999.10.10.10"),
            _base_event(6, dst_ip=12345),
            _base_event(7, timestamp=-5),
            _base_event(8, timestamp="yesterday"),
            '{"packet_id": 9, "timestamp": NaN, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP", "src_port": 1, "dst_port": 2}',
            _base_event(10, src_port=70000, dst_port=-1),
            _base_event(11, protocol="ICMP", src_port=None, dst_port=None),
            _base_event(
                12,
                protocol="UNKNOWN",
                src_ip=None,
                dst_ip=None,
                src_port=None,
                dst_port=None,
            ),
            _base_event(
                13, tcp_flags="SYN", app_protocol="HTTP", app_data=["not", "a", "dict"]
            ),
            {**_base_event(14), "packet_id": "fourteen"},
            _base_event(
                15, app_protocol="HTTP", app_data={"type": "request", "uri": "/valid"}
            ),
        ],
    )


# --- T07 - T13: Flow tracker -------------------------------------------------


def t07_tcp_handshake() -> None:
    conn = TcpConn(("192.168.1.10", 51234), ("192.168.1.20", 80))
    save_pcap(
        "T07",
        [
            (0.0, conn.pkt(True, "S")),
            (0.001, conn.pkt(False, "SA")),
            (0.002, conn.pkt(True, "A")),
        ],
    )


def t08_bidirectional() -> None:
    conn = TcpConn(("192.168.1.10", 51300), ("93.184.216.34", 80))
    request = http_message("GET /index.html HTTP/1.1", {"Host": "example.com"})
    body = b"<html>hello</html>"
    response = http_message(
        "HTTP/1.1 200 OK",
        {"Content-Type": "text/html", "Content-Length": str(len(body))},
        body,
    )
    save_pcap(
        "T08",
        [
            (0.000, conn.pkt(True, "S")),
            (0.010, conn.pkt(False, "SA")),
            (0.011, conn.pkt(True, "A")),
            (0.012, conn.pkt(True, "PA", request)),
            (0.030, conn.pkt(False, "A")),
            (0.031, conn.pkt(False, "PA", response)),
            (0.032, conn.pkt(True, "A")),
        ],
    )


def t09_tcp_close() -> None:
    server = ("192.168.1.20", 80)
    fin = TcpConn(("192.168.1.10", 51400), server)
    rst = TcpConn(("192.168.1.10", 51401), server)
    reuse = TcpConn(("192.168.1.10", 51400), server, client_isn=9000, server_isn=9500)
    save_pcap(
        "T09",
        [
            # connection 1: handshake, data, graceful close FIN/ACK from both sides
            (0.00, fin.pkt(True, "S")),
            (0.01, fin.pkt(False, "SA")),
            (0.02, fin.pkt(True, "A")),
            (0.03, fin.pkt(True, "PA", b"hello")),
            (0.04, fin.pkt(False, "A")),
            (0.05, fin.pkt(True, "FA")),
            (0.06, fin.pkt(False, "A")),
            (0.07, fin.pkt(False, "FA")),
            (0.08, fin.pkt(True, "A")),
            # connection 2: refused by the server with RST
            (1.00, rst.pkt(True, "S")),
            (1.01, rst.pkt(False, "RA")),
            # connection 3: same 5-tuple as connection 1, new SYN -> new flow (seq 2)
            (2.00, reuse.pkt(True, "S")),
            (2.01, reuse.pkt(False, "SA")),
            (2.02, reuse.pkt(True, "A")),
        ],
    )


def t10_udp_dns() -> None:
    client, resolver = ("192.168.1.10", 53530), ("8.8.8.8", 53)
    query = DNS(id=0x5101, rd=1, qd=DNSQR(qname="uit.edu.vn", qtype="A"))
    answer = DNS(
        id=0x5101,
        qr=1,
        rd=1,
        ra=1,
        qd=DNSQR(qname="uit.edu.vn", qtype="A"),
        an=DNSRR(rrname="uit.edu.vn", type="A", ttl=300, rdata="118.69.123.140"),
    )
    reply = udp(resolver, client, answer)
    reply[Ether].src, reply[Ether].dst = SERVER_MAC, CLIENT_MAC
    save_pcap("T10", [(0.0, udp(client, resolver, query)), (0.025, reply)])


def t11_concurrent_flows() -> None:
    server = ("192.168.1.20", 80)
    a = TcpConn(("192.168.1.10", 51500), server)
    b = TcpConn(("192.168.1.10", 51501), server)  # same hosts, other source port
    c = TcpConn(("192.168.1.11", 51500), server)  # other client, same port as a
    dns_q = udp(
        ("192.168.1.10", 51500),
        ("8.8.8.8", 53),
        DNS(id=1, rd=1, qd=DNSQR(qname="a.com")),
    )
    save_pcap(
        "T11",
        [
            (0.00, a.pkt(True, "S")),
            (0.01, b.pkt(True, "S")),
            (0.02, c.pkt(True, "S")),
            (0.03, a.pkt(False, "SA")),
            (0.04, dns_q),
            (0.05, c.pkt(False, "SA")),
            (0.06, b.pkt(False, "SA")),
            (0.07, a.pkt(True, "A")),
            (0.08, b.pkt(True, "A")),
            (0.09, c.pkt(True, "A")),
            (0.10, a.pkt(True, "PA", b"flow-a")),
            (0.11, c.pkt(True, "PA", b"flow-c")),
        ],
    )


def t12_idle_timeout() -> None:
    dns_client, resolver = ("192.168.1.10", 53600), ("8.8.8.8", 53)
    tcp = TcpConn(("192.168.1.10", 51600), ("192.168.1.20", 80))
    other = TcpConn(("192.168.1.30", 51601), ("192.168.1.20", 443))
    query = DNS(id=0x1201, rd=1, qd=DNSQR(qname="uit.edu.vn"))
    save_pcap(
        "T12",
        [
            (0.0, udp(dns_client, resolver, query)),  # UDP flow, idle timeout 60 s
            (0.0, tcp.pkt(True, "S")),  # TCP flow, idle timeout 300 s
            (0.1, tcp.pkt(False, "SA")),
            (0.2, tcp.pkt(True, "A")),
            (30.0, other.pkt(True, "S")),  # 30 s: nothing expired yet
            (61.0, other.pkt(True, "S")),  # 61 s > 60 s: the UDP flow is exported
            (
                90.0,
                udp(dns_client, resolver, query),
            ),  # same 5-tuple again -> new flow (seq 2)
            (
                400.0,
                other.pkt(True, "S"),
            ),  # 400 s: TCP flow (300 s) and others exported
        ],
    )


def t13_statistics() -> None:
    conn = TcpConn(("192.168.1.10", 51700), ("192.168.1.20", 8080))
    save_pcap(
        "T13",
        [
            (0.00, conn.pkt(True, "S")),  # 40 B
            (0.10, conn.pkt(False, "SA")),  # 40 B
            (0.20, conn.pkt(True, "A")),  # 40 B
            (0.50, conn.pkt(True, "PA", b"A" * 100)),  # 140 B
            (0.60, conn.pkt(True, "PA", b"B" * 200)),  # 240 B
            (0.70, conn.pkt(False, "A")),  # 40 B
            (1.00, conn.pkt(False, "PA", b"C" * 300)),  # 340 B
            (1.10, conn.pkt(True, "A")),  # 40 B
            (2.00, conn.pkt(True, "FA")),  # 40 B
            (2.10, conn.pkt(False, "FA")),  # 40 B
            (2.50, conn.pkt(True, "A")),  # 40 B
        ],
    )


CASE_NAMES = {
    "T01": "http_url_decode",
    "T02": "html_entity",
    "T03": "smtp_mime",
    "T04": "invalid_bytes",
    "T05": "normalization",
    "T06": "missing_field",
    "T07": "tcp_handshake",
    "T08": "bidirectional",
    "T09": "tcp_close",
    "T10": "udp_dns",
    "T11": "concurrent_flows",
    "T12": "idle_timeout",
    "T13": "statistics",
    "T14": "malformed_event",
}
GENERATORS: dict[str, Callable[[], None]] = {
    "T01": t01_http_url_decode,
    "T02": t02_html_entity,
    "T03": t03_smtp_mime,
    "T04": t04_invalid_bytes,
    "T05": t05_normalization,
    "T06": t06_missing_field,
    "T07": t07_tcp_handshake,
    "T08": t08_bidirectional,
    "T09": t09_tcp_close,
    "T10": t10_udp_dns,
    "T11": t11_concurrent_flows,
    "T12": t12_idle_timeout,
    "T13": t13_statistics,
    "T14": t14_malformed_event,
}


def main(argv: list[str]) -> int:
    selected = [c.upper() for c in argv] or list(GENERATORS)
    unknown = [c for c in selected if c not in GENERATORS]
    if unknown:
        print(f"unknown case(s): {', '.join(unknown)}", file=sys.stderr)
        return 1
    for case in selected:
        GENERATORS[case]()
        print(f"generated {_case_dir(case).relative_to(TEST_DIR.parent)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
