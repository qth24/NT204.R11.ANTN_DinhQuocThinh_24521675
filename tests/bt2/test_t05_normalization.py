"""T05 - Normalization: different spellings -> one consistent representation."""

from __future__ import annotations

from tests.bt2.conftest import committed, run_case


def test_t05_normalization() -> None:
    events, flows = run_case("T05")
    norm = [e["normalized"] for e in events]

    # protocol / app_protocol: "tcp", "Tcp", "udp" ... -> UPPERCASE
    assert [n["protocol"] for n in norm] == ["TCP", "TCP", "UDP", "UDP", "TCP"]
    assert [n["app_protocol"] for n in norm] == ["HTTP", "HTTP", "DNS", "DNS", None]
    assert [e["protocol"] for e in events] == [
        "tcp",
        "Tcp",
        "udp",
        "UDP",
        "TCP",
    ]  # raw kept

    # HTTP: two Host spellings -> same domain; header names lowercase + trimmed
    assert norm[0]["domain"] == norm[1]["domain"] == "www.example.com"
    assert norm[0]["http_headers"] == {
        "host": "WWW.Example.COM:8080",
        "user-agent": "curl/8.5",
        "content-type": "text/plain",
    }
    # URI path: decoded, "//" collapsed, "." and ".." resolved, never above "/"
    assert norm[0]["uri_path"] == norm[1]["uri_path"] == "/admin/users"
    assert events[0]["decoded"]["query_params"] == {"Sort": ["DESC"]}  # query apart

    # DNS: uppercase + trailing dot, and IDNA for a non-ASCII name
    assert norm[2]["domain"] == "www.uit.edu.vn"
    assert norm[3]["domain"] == "xn--bcher-kva.de"

    # IP: canonical text; leading zeros are rejected (octal ambiguity)
    assert norm[4]["dst_ip"] == "2001:db8::1"
    assert norm[4]["src_ip"] is None
    assert events[4]["reason"] == ["invalid_ip:' 192.168.001.010 '"]

    assert norm[0]["timestamp_iso"] == "2025-09-28T22:53:21.000000+00:00"
    assert [f["application_protocol"] for f in flows] == ["HTTP", "HTTP", "DNS", "DNS"]

    assert events == committed("T05", "events.jsonl")
    assert flows == committed("T05", "flows.jsonl")
