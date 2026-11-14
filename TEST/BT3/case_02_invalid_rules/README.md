# Case 02 — Rule sai cú pháp

**Mục tiêu:** rule sai cú pháp → `invalid` + reason ổn định; không dừng chương trình, không ảnh hưởng rule khác.

**Input:** `invalid.rules` (15 rule: 13 sai, 2 đúng — sid 202 và 209) + `input_events.jsonl` (1 gói `GET /`).

**Chạy:** `bash TEST/run_bt3.sh 02` · Test: `pytest tests/bt3/test_case02_invalid_rules.py`

| Dòng | Lỗi | Reason |
|---|---|---|
| 1 | thiếu `sid` | `invalid:missing_sid` |
| 3 | thiếu `msg` | `invalid:missing_msg` |
| 4 | port `80:20` | `invalid:bad_port_range:80:20` |
| 5 | direction `<-` | `invalid:bad_direction:<-` |
| 6 | `distance` không có content | `invalid:distance_without_content` |
| 7 | chuỗi `"` không đóng | `invalid:unterminated_string` |
| 8 | CIDR `/33` | `invalid:bad_ip:10.0.0.0/33` |
| 10 | trùng sid 209 (rule sau) | `invalid:duplicate_sid:209` |
| 11 | `depth:3` < độ dài `GET /` | `invalid:depth_too_small:3<5` |
| 12 | hex `\|4G\|` | `invalid:bad_hex:G` |
| 13 | `established,not_established` | `invalid:flow_conflict` |
| 14 | port 70000 | `invalid:bad_port:70000` |
| 15 | `offset` + `distance` | `invalid:offset_with_distance` |

Kết quả: `loaded=15 valid=2 invalid=13`; gói `GET /` vẫn match 2 rule hợp lệ (sid 202, 209) trong `detections.jsonl`. Test còn kiểm tra thêm các reason `bad_sid`, `bad_rev`, `bad_priority`, `bad_dsize_range`, `bad_flags`, `empty_content`, `within_too_small`, `duplicate_option`, `missing_options`.

**Kết luận: PASS**
