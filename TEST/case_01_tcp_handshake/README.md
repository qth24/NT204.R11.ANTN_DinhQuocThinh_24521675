# Case 01 — TCP handshake (SYN / SYN-ACK / ACK)

**Mục tiêu:** parser nhận diện đúng 3 bước bắt tay TCP qua `tcp_flags`, seq/ack.

**Input:** `input.pcap` (tạo bằng `generate.py`): client `192.168.1.10:51234` ↔ server `192.168.1.20:80`.

**Chạy:**
```bash
python TEST/case_01_tcp_handshake/generate.py
python main.py --pcap TEST/case_01_tcp_handshake/input.pcap -o TEST/case_01_tcp_handshake/output.jsonl
```

## Kết quả

| # | Hướng | Mong đợi `tcp_flags` | Thực tế | seq / ack | `app_protocol` | `error` |
|---|---|---|---|---|---|---|
| 1 | client → server | `["SYN"]` | `["SYN"]` | 1000 / 0 | `null` | `null` |
| 2 | server → client | `["SYN","ACK"]` | `["SYN","ACK"]` | 5000 / 1001 | `null` | `null` |
| 3 | client → server | `["ACK"]` | `["ACK"]` | 1001 / 5001 | `null` | `null` |

- `protocol = "TCP"`, IP/port đúng cả 2 chiều, `payload_length = 0` → không gán application protocol
  dù port 80 (không có payload thì không đoán HTTP).
- Tóm tắt chương trình: `packets processed: 3, events written: 3, events with error: 0, protocols: TCP=3`.

**Kết luận: PASS**
