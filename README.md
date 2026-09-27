# IDS Packet Capture & Parser

Bài tập 1 môn **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập**: module thu thập
traffic (live hoặc từ PCAP), parse qua các layer IPv4 → TCP/UDP → HTTP/DNS/SMTP và xuất
ra **Normalized IDS Event** dạng JSON Lines.

## Cài đặt

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Kiến trúc

```
Raw Packet → Network Parser (IPv4) → Transport Parser (TCP/UDP)
→ Application Protocol Detector → Application Protocol Parser
→ Normalized IDS Event → JSON Lines log
```

### Capture layer (`capture/`)

Cả hai nguồn đều trả về iterator các `RawPacket` giống nhau (`timestamp`, `data`,
`linktype`, `wire_len`, `truncated`, `source`), nên phía sau chỉ cần **một pipeline**:

| Hàm | Mô tả |
|---|---|
| `read_pcap(path)` | Đọc file `.pcap`/`.pcapng` bằng `scapy.utils.RawPcapReader`. File hỏng/cụt giữa chừng: trả các gói đọc được, log cảnh báo, không crash. |
| `live_packets(interface, bpf_filter, count, timeout)` | Bắt live bằng `scapy.AsyncSniffer` (thread nền → queue → generator). Cần quyền root. |

Lỗi không mở được nguồn (file không tồn tại, không phải PCAP, thiếu quyền, interface
sai) được báo bằng `CaptureError`.

### Network parser (`parsers/network.py`)

`parse_network(data, linktype) -> NetworkLayer`, không bao giờ raise:

1. **Bóc header link layer** theo linktype: Ethernet (1, có bỏ qua VLAN 802.1Q),
   raw IP (12/101/228), Linux cooked SLL (113), SLL2 (276), BSD loopback (0).
2. **Parse IPv4 header** (RFC 791) bằng `struct`: version, IHL, total length, id, flags
   (DF/MF), fragment offset, TTL, protocol, src/dst IP, kiểm tra checksum.
3. `payload` được cắt theo `total_length` (loại bỏ Ethernet padding) để giao cho transport parser.

Gói không phải IPv4 (ARP, IPv6...), header cụt, version/IHL sai, total length sai
đều được ghi vào `error` thay vì làm crash chương trình.

### Transport parser (`parsers/transport.py`)

`parse_transport(protocol, data, fragment_offset) -> TransportLayer`, không bao giờ raise:

- **TCP** (proto 6): src/dst port, seq, ack, window, data offset (độ dài header kể cả
  options), cờ `FIN/SYN/RST/PSH/ACK/URG/ECE/CWR/NS`; payload = phần sau header.
- **UDP** (proto 17): src/dst port, length; payload cắt theo field length.
- Protocol khác (ICMP...) → `protocol="UNKNOWN"`. Fragment IP không phải đầu tiên
  → không có header transport, ghi `error`.
- Header cụt, data offset / UDP length sai → ghi vào `error`, vẫn giữ port nếu đọc được.

## Chạy test

```bash
python -m pytest tests
```

## AI Usage

| Công cụ | Mục đích | Phần code |
|---|---|---|
| Claude Code (Claude Opus) | Thiết kế và sinh code module capture, viết unit test | `capture/raw_packet.py`, `capture/pcap_reader.py`, `capture/live_capture.py`, `tests/test_capture.py` |
| Claude Code (Claude Opus) | Sinh code IPv4 parser (bóc link layer, decode header, checksum), viết unit test | `parsers/network.py`, `tests/test_network.py` |
| Claude Code (Claude Opus) | Sinh code TCP/UDP parser (ports, flags, seq/ack, UDP length), viết unit test | `parsers/transport.py`, `tests/test_transport.py` |
