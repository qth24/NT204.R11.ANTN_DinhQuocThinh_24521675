# Case 12 — `flags` và `dsize`

**Mục tiêu:** `flags` đúng semantics Snort (không modifier = chính xác; `+` có tất cả; `*` có ít nhất một; `!` không có cờ nào; mask sau dấu `,`); `dsize` so với độ dài payload — kể cả pure ACK `dsize:0`; rule có `flags` không match UDP.

**Input:** `flags_dsize.rules` (10 rule) + `input_events.jsonl` (8 gói: SYN, SYN/ACK, pure ACK, PSH/ACK 12 byte, FIN/ACK, không cờ, UDP 5 byte, PSH/ACK 8 byte).

**Chạy:** `bash TEST/run_bt3.sh 12` · Test: `pytest tests/bt3/test_case12_flags_dsize.py`

| Sid | Rule | Gói match |
|---|---|---|
| 1201 | `flags:S` (chính xác) | 1 (không match SYN/ACK) |
| 1202 | `flags:+SA` | 2 |
| 1203 | `flags:*FR` | 5 |
| 1204 | `flags:!S` | 3, 4, 5, 6, 8 (không SYN; UDP gói 7 bị loại ở header) |
| 1205 | `flags:A,P` (bỏ qua PSH) | 3, 4, 8 |
| 1206 | `flags:0` | 6 |
| 1207 | `dsize:0` | 1, 2, 3, 5, 6 |
| 1208 | `dsize:>10` | 4 (12 byte) |
| 1209 | `dsize:5<>8` (inclusive) | 8 (đúng 8 byte) |
| 1210 | `flags:A; dsize:0` | 3 (pure ACK) |

Thực tế khớp bảng (xem `detections.jsonl`). Test tham số hóa thêm từng modifier, biên của `<`, `>`, `<>` và chế độ `engine.dsize_range_inclusive=false`. **Kết luận: PASS**
