# T13 — Statistics

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): một kết nối TCP `192.168.1.10:51700` (A) ↔ `192.168.1.20:8080` (B), 11 gói với kích thước và thời điểm biết trước.

**Chạy:** `bash TEST/run_bt2.sh T13` · Test: `pytest tests/bt2/test_t13_statistics.py`

**Định nghĩa `byte_count`:** tổng field IPv4 *total length* (IP header + TCP/UDP header + payload, không tính Ethernet).

| # | t (s) | Hướng | Flags | Payload | IP total length |
|---|---|---|---|---|---|
| 1 | 0.0 | fwd | SYN | 0 | 40 |
| 2 | 0.1 | bwd | SYN,ACK | 0 | 40 |
| 3 | 0.2 | fwd | ACK | 0 | 40 |
| 4 | 0.5 | fwd | PSH,ACK | 100 | 140 |
| 5 | 0.6 | fwd | PSH,ACK | 200 | 240 |
| 6 | 0.7 | bwd | ACK | 0 | 40 |
| 7 | 1.0 | bwd | PSH,ACK | 300 | 340 |
| 8 | 1.1 | fwd | ACK | 0 | 40 |
| 9 | 2.0 | fwd | FIN,ACK | 0 | 40 |
| 10 | 2.1 | bwd | FIN,ACK | 0 | 40 |
| 11 | 2.5 | fwd | ACK | 0 | 40 |

| Thống kê | Mong đợi (tính tay) | Thực tế |
|---|---|---|
| `packet_count` / `byte_count` | 11 / 1040 | 11 / 1040 |
| `fwd_packet_count` / `fwd_byte_count` | 7 / 580 | 7 / 580 |
| `bwd_packet_count` / `bwd_byte_count` | 4 / 460 | 4 / 460 |
| `syn_count` / `ack_count` / `fin_count` / `rst_count` | 2 / 10 / 2 / 0 | 2 / 10 / 2 / 0 |
| `duration` | 2.5 − 0.0 = 2.5 s | 2.5 |
| `state` / `end_reason` | CLOSED / fin | CLOSED / fin |

- Pure ACK (gói 3, 6, 8, 11) vẫn được đếm. `application_protocol = HTTP` do port 8080 thuộc danh sách port dự phòng HTTP của BT1.

**Kết luận: PASS**
