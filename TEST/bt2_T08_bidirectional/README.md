# T08 — Bidirectional

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): một kết nối HTTP đầy đủ giữa `192.168.1.10:51300` (A) và `93.184.216.34:80` (B): handshake, GET, ACK, response 200, ACK.

**Chạy:** `bash TEST/run_bt2.sh T08` · Test: `pytest tests/bt2/test_t08_bidirectional.py`

| # | Nguồn | `tcp_flags` | IP total length | `direction` | `flow_id` |
|---|---|---|---|---|---|
| 1 | A | SYN | 40 | forward | `TCP-1682fa2746d3-1` |
| 2 | B | SYN,ACK | 40 | backward | `TCP-1682fa2746d3-1` |
| 3 | A | ACK | 40 | forward | `TCP-1682fa2746d3-1` |
| 4 | A | PSH,ACK (GET) | 87 | forward | `TCP-1682fa2746d3-1` |
| 5 | B | ACK | 40 | backward | `TCP-1682fa2746d3-1` |
| 6 | B | PSH,ACK (200 OK) | 122 | backward | `TCP-1682fa2746d3-1` |
| 7 | A | ACK | 40 | forward | `TCP-1682fa2746d3-1` |

- Cả hai chiều cho **cùng canonical key** → cùng `flow_id`; `forward` = gói do A (bên gửi SYN) gửi.
- Flow: `fwd_packet_count = 4`, `fwd_byte_count = 207` (40+40+87+40); `bwd_packet_count = 3`, `bwd_byte_count = 202` (40+40+122); `byte_count = 409`; `application_protocol = HTTP`.

**Kết luận: PASS**
