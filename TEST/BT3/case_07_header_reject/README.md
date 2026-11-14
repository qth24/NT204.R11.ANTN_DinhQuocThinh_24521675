# Case 07 — Header không match → loại trước content

**Mục tiêu:** chứng minh thứ tự rẻ → đắt: rule sai header bị loại *trước* khi content matcher chạy.

**Input:** `header_reject.rules` — 701 (header đúng + content `GET`), 702 (port 443), 703 (src ip `10.9.9.9`), 704 (UDP); `input_events.jsonl` — gói 1 `GET /...`, gói 2 `hello`, đều TCP `10.0.0.1:4000 → 10.0.0.2:80`.

**Chạy:** `bash TEST/run_bt3.sh 07` · Test: `pytest tests/bt3/test_case07_header_reject.py`

Cách chứng minh: test thay `content_matcher` của `RuleMatcher` bằng hàm đếm lời gọi.

| Cấu hình | Candidates | Rule bị header loại | Số lần content matcher được gọi |
|---|---|---|---|
| có index | 2 (701, 703; index đã bỏ 702 port, 704 protocol) | 1 (703) | **1** (chỉ 701) |
| không index (duyệt hết) | 4 | 3 (702, 703, 704) | **1** (chỉ 701) |

Reason: 703 → `direction`, 704 → `protocol`. End-to-end: `detections.jsonl` chỉ có (gói 1, sid 701); `run.log` ghi `rejected_by_header=2`. **Kết luận: PASS**
