"""Unit tests for the DNS parser."""

from __future__ import annotations

import json
import struct

from scapy.layers.dns import (
    DNS,
    DNSQR,
    DNSRR,
    DNSRRMX,
    DNSRROPT,
    DNSRRSOA,
    DNSRRSRV,
)

from parsers.app.dns_parser import parse_dns


def _header(qd: int = 1, an: int = 0, flags: int = 0x0100, msg_id: int = 7) -> bytes:
    return struct.pack("!HHHHHH", msg_id, flags, qd, an, 0, 0)


def _name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def test_query() -> None:
    msg = bytes(DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com", qtype="A")))
    result = parse_dns(msg)
    data = result.data

    assert result.error is None
    assert data["id"] == 0x1234
    assert data["type"] == "query"
    assert data["opcode"] == "QUERY"
    assert data["flags"]["rd"] is True
    assert data["counts"]["questions"] == 1
    assert data["questions"] == [{"name": "example.com.", "type": "A", "class": "IN"}]
    assert data["answers"] == []


def test_response_with_answers() -> None:
    msg = bytes(
        DNS(
            id=1,
            qr=1,
            aa=1,
            ra=1,
            qd=DNSQR(qname="www.example.com"),
            an=[
                DNSRR(rrname="www.example.com", type="CNAME", rdata="example.com"),
                DNSRR(rrname="example.com", type="A", ttl=300, rdata="93.184.216.34"),
                DNSRR(rrname="example.com", type="AAAA", rdata="2606:2800::1"),
            ],
        )
    )
    result = parse_dns(msg)
    data = result.data

    assert result.error is None
    assert data["type"] == "response"
    assert data["rcode_name"] == "NOERROR"
    assert data["flags"]["aa"] and data["flags"]["ra"]
    assert [a["type"] for a in data["answers"]] == ["CNAME", "A", "AAAA"]
    assert data["answers"][0]["data"] == "example.com."
    assert data["answers"][1] == {
        "name": "example.com.",
        "type": "A",
        "class": "IN",
        "ttl": 300,
        "data": "93.184.216.34",
    }
    assert data["answers"][2]["data"] == "2606:2800::1"


def test_nxdomain() -> None:
    msg = bytes(DNS(qr=1, rcode=3, qd=DNSQR(qname="nope.invalid")))
    data = parse_dns(msg).data
    assert data["rcode"] == 3
    assert data["rcode_name"] == "NXDOMAIN"


def test_mx_txt_soa_srv_and_opt_records() -> None:
    msg = bytes(
        DNS(
            qr=1,
            qd=DNSQR(qname="example.com", qtype="MX"),
            an=[
                DNSRRMX(
                    rrname="example.com", preference=10, exchange="mail.example.com"
                ),
                DNSRR(rrname="example.com", type="TXT", rdata=["v=spf1 -all", "x"]),
                DNSRRSRV(
                    rrname="_sip._tcp.example.com",
                    priority=1,
                    weight=5,
                    port=5060,
                    target="sip.example.com",
                ),
            ],
            ns=DNSRRSOA(
                rrname="example.com",
                mname="ns1.example.com",
                rname="admin.example.com",
                serial=2024010101,
            ),
            ar=DNSRROPT(rclass=4096),
        )
    )
    result = parse_dns(msg)
    data = result.data

    assert result.error is None
    mx, txt, srv = data["answers"]
    assert mx["data"] == {"preference": 10, "exchange": "mail.example.com."}
    assert txt["data"] == ["v=spf1 -all", "x"]
    assert srv["data"]["port"] == 5060
    assert srv["data"]["target"] == "sip.example.com."
    soa = data["authorities"][0]["data"]
    assert soa["mname"] == "ns1.example.com."
    assert soa["serial"] == 2024010101
    opt = data["additionals"][0]
    assert opt["type"] == "OPT"
    assert opt["udp_payload_size"] == 4096


def test_compression_pointer() -> None:
    # Answer name is a pointer (0xC00C) to the question name at offset 12
    msg = (
        _header(qd=1, an=1, flags=0x8180)
        + _name("example.com")
        + struct.pack("!HH", 1, 1)
        + b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + bytes([1, 2, 3, 4])
    )
    result = parse_dns(msg)
    assert result.error is None
    assert result.data["answers"][0]["name"] == "example.com."
    assert result.data["answers"][0]["data"] == "1.2.3.4"


def test_compression_loop_does_not_hang() -> None:
    # Question name is a pointer to itself
    msg = _header() + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    result = parse_dns(msg)
    assert "bad compression pointer" in result.error


def test_pointer_out_of_bounds() -> None:
    msg = _header() + b"\xc0\xff" + struct.pack("!HH", 1, 1)
    assert "bad compression pointer" in parse_dns(msg).error


def test_truncated_message_keeps_parsed_part() -> None:
    full = bytes(
        DNS(
            qr=1,
            qd=DNSQR(qname="example.com"),
            an=DNSRR(rrname="example.com", rdata="1.2.3.4"),
        )
    )
    result = parse_dns(full[:-3])
    assert "Malformed DNS message" in result.error
    assert result.data["questions"][0]["name"] == "example.com."
    assert result.data["answers"] == []


def test_header_counts_larger_than_message() -> None:
    msg = _header(qd=1, an=500) + _name("a.com") + struct.pack("!HH", 1, 1)
    result = parse_dns(msg)
    assert result.data["counts"]["answers"] == 500
    assert "truncated" in result.error


def test_truncated_header_and_empty() -> None:
    assert "Truncated DNS header" in parse_dns(b"\x00\x01\x02").error
    assert "Truncated DNS header" in parse_dns(b"").error


def test_dns_over_tcp_length_prefix() -> None:
    msg = bytes(DNS(qd=DNSQR(qname="example.com")))
    result = parse_dns(struct.pack("!H", len(msg)) + msg, tcp=True)
    assert result.error is None
    assert result.data["questions"][0]["name"] == "example.com."
    assert parse_dns(b"\x00", tcp=True).error is not None


def test_binary_label_is_escaped_and_json_safe() -> None:
    msg = _header() + b"\x04\xff\xfeab\x03com\x00" + struct.pack("!HH", 16, 1)
    result = parse_dns(msg)
    assert result.error is None
    assert result.data["questions"][0]["name"] == "\\xff\\xfeab.com."
    assert result.data["questions"][0]["type"] == "TXT"
    json.dumps(result.data)


def test_unknown_type_and_bad_rdata_fall_back_to_hex() -> None:
    msg = (
        _header(qd=0, an=2, flags=0x8000)
        + _name("x.com")
        + struct.pack("!HHIH", 999, 1, 0, 3)
        + b"\xaa\xbb\xcc"
        + _name("y.com")
        + struct.pack("!HHIH", 1, 1, 0, 2)  # A record with 2 bytes: invalid
        + b"\x01\x02"
    )
    result = parse_dns(msg)
    assert result.error is None
    assert result.data["answers"][0]["type"] == "TYPE999"
    assert result.data["answers"][0]["data"] == "aabbcc"
    assert result.data["answers"][1]["data"] == "0102"


def test_root_name() -> None:
    msg = _header() + b"\x00" + struct.pack("!HH", 2, 1)
    assert parse_dns(msg).data["questions"][0]["name"] == "."
