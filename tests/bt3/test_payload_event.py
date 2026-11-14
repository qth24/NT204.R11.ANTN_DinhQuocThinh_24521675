"""BT3 prerequisite: the event carries the transport payload."""

import base64
import json

from config import Config, EngineConfig
from core.logger import JsonLinesWriter
from core.pipeline import Pipeline


def _event(**extra):
    event = {
        "packet_id": 1,
        "timestamp": 1.0,
        "src_ip": "10.0.0.1",
        "dst_ip": "10.0.0.2",
        "protocol": "TCP",
        "src_port": 1234,
        "dst_port": 9999,
        "tcp_flags": ["ACK"],
        "app_protocol": None,
        "app_data": {},
        "error": None,
    }
    event.update(extra)
    return event


def test_payload_attached_from_bytes_and_cut():
    cfg = Config(engine=EngineConfig(max_payload_bytes=4))
    pipe = Pipeline(config=cfg, keep_payload=True)
    out = pipe.enrich(_event(payload_length=10), b"0123456789")
    assert out["payload"] == b"0123"
    assert out["payload_length"] == 10  # dsize keeps the real length


def test_payload_from_jsonl_b64_and_dsize_for_empty():
    pipe = Pipeline(keep_payload=True)
    b64 = base64.b64encode(b"abc").decode()
    out = pipe.enrich(_event(payload_b64=b64), None)
    assert out["payload"] == b"abc" and out["payload_length"] == 3
    out = pipe.enrich(_event(payload_b64=""), None)
    assert out["payload"] == b"" and out["payload_length"] == 0


def test_payload_off_by_default():
    out = Pipeline().enrich(_event(), b"abc")
    assert "payload" not in out


def test_writer_writes_payload_b64(tmp_path):
    path = tmp_path / "e.jsonl"
    event = {"packet_id": 1, "payload": b"\x00hi"}
    with JsonLinesWriter(str(path)) as writer:
        writer.write(event)
    line = json.loads(path.read_text())
    assert "payload" not in line
    assert base64.b64decode(line["payload_b64"]) == b"\x00hi"
    assert event["payload"] == b"\x00hi"  # caller's dict untouched
