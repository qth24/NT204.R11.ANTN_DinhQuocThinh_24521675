# T07 — TCP handshake

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): `192.168.1.10:51234` ↔ `192.168.1.20:80`, SYN (seq 1000) → SYN/ACK (seq 5000, ack 1001) → ACK.

**Chạy:** `bash TEST/run_bt2.sh T07` · Test: `pytest tests/bt2/test_t07_tcp_handshake.py`

| Gói | `tcp_flags` | `direction` | State của flow sau gói (test chạy lần lượt 1, 2, 3 gói) |
|---|---|---|---|
| 1 | `["SYN"]` | `forward` | `NEW` |
| 2 | `["SYN","ACK"]` | `backward` | `HANDSHAKE` |
| 3 | `["ACK"]` | `forward` | `ESTABLISHED` |

`flows.jsonl` — **1 flow** `TCP-ec59185c781a-1`:
- `state = ESTABLISHED`, `endpoint_a = 192.168.1.10:51234` (bên gửi SYN), `endpoint_b = 192.168.1.20:80`
- `packet_count = 3`, `byte_count = 120` (3 × IP total length 40), `syn_count = 2`, `ack_count = 2`, `notes = []`
- `end_reason = end_of_capture` (PCAP kết thúc khi kết nối còn mở → flush)

**Kết luận: PASS**
