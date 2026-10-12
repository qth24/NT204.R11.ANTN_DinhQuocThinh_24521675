# T14 — Malformed event

**Input:** `input_events.jsonl` (tạo bởi `tests/gen_pcaps_bt2.py`): 15 dòng, gồm dòng JSON hỏng, giá trị không phải object, thiếu field, sai kiểu, ngoài khoảng, protocol không hỗ trợ.

**Chạy:** `bash TEST/run_bt2.sh T14` — chạy 2 lần:
- mặc định (`on_invalid = on_unsupported = mark`) → `events.jsonl`, `flows.jsonl`
- `--set preprocess.on_invalid=drop --set preprocess.on_unsupported=drop` → `events_drop.jsonl`, `flows_drop.jsonl`

Test: `pytest tests/bt2/test_t14_malformed_event.py`

| # | Input | `preprocess_status` | `reason` |
|---|---|---|---|
| 1 | `{this is not json` | invalid | 5 × `missing_field:*` + `parse_error` (`error: input line 1: invalid JSON`) |
| 2–3 | `[1, 2, 3]`, `"just a string"` | invalid | như trên (`not a JSON object`) |
| 4 | chỉ có `timestamp`, `src_ip` | invalid | `missing_field:packet_id/dst_ip/protocol` |
| 5 | `src_ip = 999.10.10.10` | invalid | `invalid_ip:'999.10.10.10'` |
| 6 | `dst_ip = 12345` (số) | invalid | `invalid_ip:12345` |
| 7 / 8 / 9 | timestamp `-5` / `"yesterday"` / `NaN` | invalid | `invalid_timestamp:...` |
| 10 | port `70000`, `-1` | partial | `invalid_port:70000`, `invalid_port:-1` |
| 11 | `protocol = ICMP` | invalid | `unsupported_protocol:ICMP` |
| 12 | `UNKNOWN`, không có IP | invalid | `missing_field:src_ip/dst_ip`, `unsupported_protocol:UNKNOWN` |
| 13 | `tcp_flags = "SYN"`, `app_data = [list]` | partial | `invalid_field:tcp_flags`, `decode_failed` (`app_data is not an object (list)`) |
| 14 | `packet_id = "fourteen"` | invalid | `invalid_packet_id:'fourteen'` |
| 15 | event hợp lệ | valid | `[]` |

**Chế độ `mark`:** 15 event đều được ghi (`mark`/`pass`). Chỉ event có thời gian + endpoint dùng được mới vào flow → 3 flow (#13, #14, #15); timestamp âm/NaN không bao giờ vào flow.

**Chế độ `drop`:** 12 event invalid có `processing_action = drop` (vẫn ghi log vì `log_dropped = true`) và **không vào FlowTracker** (`flow_id = null`) → còn 2 flow (#13, #15).

- Không exception, exit code 0 ở cả hai chế độ.
- Case này phát hiện 2 lỗi, đã sửa trước khi ghi kết quả: tracker nhận timestamp âm/NaN (làm hỏng so sánh timeout) và decoder báo lỗi nội bộ khó hiểu khi `app_data` không phải object — commit *Fix flow tracker accepting invalid timestamps*, *Fix decoder error message for non-object app_data*.

**Kết luận: PASS**
