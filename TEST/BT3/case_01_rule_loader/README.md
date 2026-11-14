# Case 01 — Rule loader

**Mục tiêu:** chỉ dòng rule thật mới được đưa sang parser; comment, dòng trống, rule bị comment (`#alert ...`) bị bỏ; rule viết trên 2 dòng (`\`) được nối lại.

**Input:** `case.rules` (4 rule + 3 dòng comment/trống + 1 rule bị comment) và `input_events.jsonl` (1 gói `GET /`).

**Chạy:** `bash TEST/run_bt3.sh 01` · Test: `pytest tests/bt3/test_case01_rule_loader.py`

| Mong đợi | Thực tế |
|---|---|
| 4 dòng rule vào parser (dòng 4, 7, 8, 10) | 4 (`loaded=4`) |
| 3 valid (sid 101, 103, 104), 1 invalid (`invalid:missing_sid`, dòng 10) | `valid=3 invalid=1 unsupported=0 disabled=0` |
| rule `#alert ... sid:102` không được bật lại | sid 102 không có trong repository |
| `engine.disabled_sids=103` → `disabled=1`; `engine.disabled_rule_files=case.rules` → `disabled=4` | đúng |
| file không tồn tại → warning, vẫn nạp file khác | đúng |
| detection: chỉ sid 101 cho gói `GET /` | `detections.jsonl` có 1 dòng, sid 101 |

Output: `report.json` (summary, problems, rule objects), `detections.jsonl`, `events.jsonl`, `flows.jsonl`, `run.log`.

**Kết luận: PASS**
