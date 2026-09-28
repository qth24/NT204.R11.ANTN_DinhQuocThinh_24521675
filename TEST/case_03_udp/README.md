# Case 03 — UDP

**Mục tiêu:** parse UDP header (port, length) và payload; `tcp_flags` rỗng; không gán
application protocol cho service không hỗ trợ; datagram rỗng không gây lỗi.

**Input:** `input.pcap` (tạo bằng `generate.py`): `172.16.0.3:40001` ↔ `172.16.0.9:9999`.

**Chạy:**
```bash
python TEST/case_03_udp/generate.py
python main.py --pcap TEST/case_03_udp/input.pcap -o TEST/case_03_udp/output.jsonl
```

## Kết quả

| # | Hướng | `protocol` | `ip_protocol` | `tcp_flags` | `payload_length` | `payload_preview` | `app_protocol` | `error` |
|---|---|---|---|---|---|---|---|---|
| 1 | client → server | `UDP` | 17 | `[]` | 10 | `"PING seq=1"` | `null` | `null` |
| 2 | server → client | `UDP` | 17 | `[]` | 10 | `"PONG seq=1"` | `null` | `null` |
| 3 | client → server | `UDP` | 17 | `[]` | 0 | `null` | `null` | `null` |

- Port nguồn/đích đảo chiều đúng ở gói trả lời.
- Datagram rỗng (UDP length = 8) được parse bình thường, không báo lỗi.
- Tóm tắt: `packets processed: 3, events with error: 0, protocols: UDP=3`.

**Kết luận: PASS**
