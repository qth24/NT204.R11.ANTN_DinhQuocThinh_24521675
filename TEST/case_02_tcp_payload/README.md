# Case 02 — TCP có payload

**Mục tiêu:** parse TCP segment mang dữ liệu: port, cờ, seq/ack, độ dài và nội dung payload,
kể cả payload nhị phân; không gán nhầm application protocol cho service lạ (port 9000).

**Input:** `input.pcap` (tạo bằng `generate.py`): `10.0.0.5:50000` ↔ `10.0.0.8:9000`,
1 segment text (40 byte), 1 ACK, 1 segment nhị phân 256 byte (`0x00..0xff`).

**Chạy:**
```bash
python TEST/case_02_tcp_payload/generate.py
python main.py --pcap TEST/case_02_tcp_payload/input.pcap -o TEST/case_02_tcp_payload/output.jsonl
```

## Kết quả

| # | Hướng | `tcp_flags` | seq / ack | `payload_length` | `payload_preview` | `app_protocol` | `error` |
|---|---|---|---|---|---|---|---|
| 1 | client → server | `["PSH","ACK"]` | 2001 / 7001 | 40 | `"Hello IDS, this is a plain text message\n"` | `null` | `null` |
| 2 | server → client | `["ACK"]` | 7001 / 2041 | 0 | `null` | `null` | `null` |
| 3 | server → client | `["PSH","ACK"]` | 7001 / 2041 | 256 | `"\\x00\\x01...\t\n..."` (128 byte đầu) | `null` | `null` |

- ACK của server = 2001 + 40 byte payload = 2041 → seq/ack được đọc đúng.
- Payload nhị phân không làm lỗi decode: byte không in được hiển thị `\xNN`, output vẫn là JSON hợp lệ.
- Port 9000 không thuộc HTTP/DNS/SMTP và payload không khớp chữ ký nào → `app_protocol = null`.

**Kết luận: PASS**
