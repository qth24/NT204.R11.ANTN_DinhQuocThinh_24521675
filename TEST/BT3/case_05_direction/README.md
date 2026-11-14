# Case 05 — Direction `->` và `<>`

**Mục tiêu:** `->` chỉ match chiều thuận; `<>` match cả hai chiều (so theo header của gói hiện tại, không phụ thuộc flow).

**Input:** `direction.rules` — 501 `10.0.0.1 any -> 10.0.0.2 80`, 502 `10.0.0.1 any <> 10.0.0.2 80`; `input_events.jsonl` 3 gói.

**Chạy:** `bash TEST/run_bt3.sh 05` · Test: `pytest tests/bt3/test_case05_direction.py`

| Gói | Hướng | 501 (`->`) | 502 (`<>`) |
|---|---|---|---|
| 1 | `10.0.0.1:4000 → 10.0.0.2:80` | match | match |
| 2 | `10.0.0.2:80 → 10.0.0.1:4000` (đảo) | không (`direction`) | match |
| 3 | `10.0.0.1:4000 → 10.0.0.3:80` | không | không |

Thực tế (`detections.jsonl`): gói 1 → [501, 502], gói 2 → [502], gói 3 → không có. **Kết luận: PASS**
