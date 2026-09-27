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

## Chạy test

```bash
python -m pytest tests
```

## AI Usage

| Công cụ | Mục đích | Phần code |
|---|---|---|
| Claude Code (Claude Opus) | Thiết kế và sinh code module capture, viết unit test | `capture/raw_packet.py`, `capture/pcap_reader.py`, `capture/live_capture.py`, `tests/test_capture.py` |
