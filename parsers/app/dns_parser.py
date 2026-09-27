"""DNS parser (RFC 1035): header, questions and resource records.

Input: UDP payload (or TCP payload with ``tcp=True``) classified as DNS by
``parsers.app_detector``.
Output: ``AppResult`` whose ``data`` is:

    {"id", "type": "query" | "response", "opcode", "rcode", "rcode_name",
     "flags": {"aa", "tc", "rd", "ra"},
     "counts": {"questions", "answers", "authorities", "additionals"},
     "questions": [{"name", "type", "class"}],
     "answers" / "authorities" / "additionals":
         [{"name", "type", "class", "ttl", "data"}]}
"""

from __future__ import annotations

import ipaddress
import struct
from typing import Any

from parsers.app import AppResult

HEADER_LEN = 12
MAX_NAME_LEN = 255
MAX_POINTER_JUMPS = 20  # a longer chain means a compression loop
MAX_RDATA_HEX = 64  # bytes of unknown RDATA kept (as hex)

TYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    64: "SVCB",
    65: "HTTPS",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
    257: "CAA",
}
CLASS_NAMES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}
OPCODE_NAMES = {0: "QUERY", 1: "IQUERY", 2: "STATUS", 4: "NOTIFY", 5: "UPDATE"}
RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


class DNSFormatError(Exception):
    """Raised internally when the message is truncated or inconsistent."""


def parse_dns(payload: bytes, tcp: bool = False) -> AppResult:
    """Parse a DNS message.

    Input: payload bytes; ``tcp=True`` strips the 2-byte length prefix used
    by DNS over TCP.
    Output: AppResult. On a truncated/malformed message the records decoded
    before the problem are kept and ``error`` explains what went wrong.
    """
    try:
        msg = payload
        if tcp:
            if len(msg) < 2:
                return AppResult(error="DNS over TCP: missing length prefix")
            msg = msg[2:]
        return _parse(msg)
    except Exception as exc:  # noqa: BLE001 - a parser bug must not stop the IDS
        return AppResult(error=f"DNS parse error: {exc}")


def _parse(msg: bytes) -> AppResult:
    if len(msg) < HEADER_LEN:
        return AppResult(
            error=f"Truncated DNS header: {len(msg)} bytes (need {HEADER_LEN})"
        )

    msg_id, flags, qdcount, ancount, nscount, arcount = struct.unpack_from(
        "!HHHHHH", msg
    )
    opcode = (flags >> 11) & 0x0F
    rcode = flags & 0x0F
    data: dict[str, Any] = {
        "id": msg_id,
        "type": "response" if flags & 0x8000 else "query",
        "opcode": OPCODE_NAMES.get(opcode, str(opcode)),
        "rcode": rcode,
        "rcode_name": RCODE_NAMES.get(rcode, str(rcode)),
        "flags": {
            "aa": bool(flags & 0x0400),  # authoritative answer
            "tc": bool(flags & 0x0200),  # truncated (retry over TCP)
            "rd": bool(flags & 0x0100),  # recursion desired
            "ra": bool(flags & 0x0080),  # recursion available
        },
        "counts": {
            "questions": qdcount,
            "answers": ancount,
            "authorities": nscount,
            "additionals": arcount,
        },
        "questions": [],
        "answers": [],
        "authorities": [],
        "additionals": [],
    }

    offset = HEADER_LEN
    try:
        for _ in range(qdcount):
            question, offset = _read_question(msg, offset)
            data["questions"].append(question)
        for section, count in (
            ("answers", ancount),
            ("authorities", nscount),
            ("additionals", arcount),
        ):
            for _ in range(count):
                record, offset = _read_record(msg, offset)
                data[section].append(record)
    except DNSFormatError as exc:
        return AppResult(data=data, error=f"Malformed DNS message: {exc}")

    return AppResult(data=data)


def _read_question(msg: bytes, offset: int) -> tuple[dict[str, Any], int]:
    name, offset = _read_name(msg, offset)
    _need(msg, offset, 4, "question type/class")
    qtype, qclass = struct.unpack_from("!HH", msg, offset)
    return {
        "name": name,
        "type": _type_name(qtype),
        "class": _class_name(qclass),
    }, offset + 4


def _read_record(msg: bytes, offset: int) -> tuple[dict[str, Any], int]:
    """Resource record: NAME, TYPE, CLASS, TTL, RDLENGTH, RDATA."""
    name, offset = _read_name(msg, offset)
    _need(msg, offset, 10, "record header")
    rtype, rclass, ttl, rdlength = struct.unpack_from("!HHIH", msg, offset)
    offset += 10
    _need(msg, offset, rdlength, f"{_type_name(rtype)} record data")
    record: dict[str, Any] = {
        "name": name,
        "type": _type_name(rtype),
        "class": _class_name(rclass),
        "ttl": ttl,
        "data": _decode_rdata(msg, offset, rtype, rdlength),
    }
    if rtype == 41:  # EDNS OPT pseudo-record: CLASS holds the UDP payload size
        record["class"] = None
        record["udp_payload_size"] = rclass
    return record, offset + rdlength


def _decode_rdata(msg: bytes, offset: int, rtype: int, length: int) -> Any:
    """Decode RDATA for common types; others are returned as hex."""
    rdata = msg[offset : offset + length]
    try:
        if rtype == 1 and length == 4:  # A
            return str(ipaddress.IPv4Address(rdata))
        if rtype == 28 and length == 16:  # AAAA
            return str(ipaddress.IPv6Address(rdata))
        if rtype in (2, 5, 12):  # NS, CNAME, PTR - names may use compression
            return _read_name(msg, offset)[0]
        if rtype == 15:  # MX
            (preference,) = struct.unpack_from("!H", rdata)
            return {
                "preference": preference,
                "exchange": _read_name(msg, offset + 2)[0],
            }
        if rtype == 16:  # TXT: sequence of <length><text>
            return _read_txt(rdata)
        if rtype == 6:  # SOA
            mname, pos = _read_name(msg, offset)
            rname, pos = _read_name(msg, pos)
            serial, refresh, retry, expire, minimum = struct.unpack_from(
                "!IIIII", msg, pos
            )
            return {
                "mname": mname,
                "rname": rname,
                "serial": serial,
                "refresh": refresh,
                "retry": retry,
                "expire": expire,
                "minimum": minimum,
            }
        if rtype == 33:  # SRV
            priority, weight, port = struct.unpack_from("!HHH", rdata)
            return {
                "priority": priority,
                "weight": weight,
                "port": port,
                "target": _read_name(msg, offset + 6)[0],
            }
    except (DNSFormatError, struct.error, ValueError):
        pass  # fall through to hex: bad RDATA must not lose the whole record
    return rdata[:MAX_RDATA_HEX].hex()


def _read_txt(rdata: bytes) -> list[str]:
    strings = []
    pos = 0
    while pos < len(rdata):
        length = rdata[pos]
        strings.append(
            rdata[pos + 1 : pos + 1 + length].decode("utf-8", errors="replace")
        )
        pos += 1 + length
    return strings


def _read_name(msg: bytes, offset: int) -> tuple[str, int]:
    """Read a domain name, following compression pointers (RFC 1035 4.1.4).

    Returns (name, offset just after the name *in the original position*).
    A label byte starting with bits 11 is a pointer: the remaining 14 bits
    are an offset into the message where the rest of the name is stored.
    """
    labels: list[str] = []
    total_len = 0
    jumps = 0
    end_offset: int | None = None  # where parsing resumes after the name
    pos = offset

    while True:
        _need(msg, pos, 1, "domain name")
        length = msg[pos]
        if length == 0:
            pos += 1
            break
        if length & 0xC0 == 0xC0:  # compression pointer
            _need(msg, pos, 2, "compression pointer")
            target = struct.unpack_from("!H", msg, pos)[0] & 0x3FFF
            if end_offset is None:
                end_offset = pos + 2
            jumps += 1
            if jumps > MAX_POINTER_JUMPS or target >= len(msg):
                raise DNSFormatError(f"bad compression pointer to offset {target}")
            pos = target
            continue
        if length & 0xC0:
            raise DNSFormatError(f"unsupported label type 0x{length:02x}")
        _need(msg, pos + 1, length, "label")
        label = msg[pos + 1 : pos + 1 + length]
        total_len += length + 1
        if total_len > MAX_NAME_LEN:
            raise DNSFormatError("domain name longer than 255 bytes")
        # Non-ASCII bytes are shown as \xNN so the name stays readable and
        # JSON-safe (useful for spotting DNS tunnelling / exfiltration).
        labels.append(label.decode("ascii", errors="backslashreplace"))
        pos += 1 + length

    name = ".".join(labels) + "." if labels else "."
    return name, end_offset if end_offset is not None else pos


def _need(msg: bytes, offset: int, length: int, what: str) -> None:
    if offset + length > len(msg):
        raise DNSFormatError(
            f"truncated {what} at offset {offset} "
            f"(need {length} bytes, {max(len(msg) - offset, 0)} left)"
        )


def _type_name(rtype: int) -> str:
    return TYPE_NAMES.get(rtype, f"TYPE{rtype}")  # RFC 3597 notation


def _class_name(rclass: int) -> str:
    # mDNS uses the top bit as unicast-response / cache-flush flag
    return CLASS_NAMES.get(rclass & 0x7FFF, f"CLASS{rclass}")
