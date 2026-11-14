# Case 11 — Hai content với `distance` / `within`

**Mục tiêu:** content sau tìm trong cửa sổ `[end_prev + distance, +within)`; `distance` có thể âm; content trước xuất hiện nhiều lần → thử mọi vị trí (backtracking, giới hạn `engine.max_content_backtrack`).

**Input:** `distance_within.rules` (8 rule), gói 1 payload `user=admin&pass=1234`, gói 2 payload `AB-AB-XY`.

**Chạy:** `bash TEST/run_bt3.sh 11` · Test: `pytest tests/bt3/test_case11_distance_within.py`

| Sid | Rule | Payload | Kết quả |
|---|---|---|---|
| 1101 | `user=` → `admin` distance 0 within 5 | gói 1 | **match** (admin @5, cửa sổ [5,10)) |
| 1102 | `user=` → `pass` distance 0 within 5 | gói 1 | không (pass @11, ngoài within) |
| 1103 | như 1102, within 15 | gói 1 | **match** (@11) |
| 1104 | `user=` → `pass=` distance 6 within 5 | gói 1 | **match** (start 5+6=11) |
| 1105 | distance 7 | gói 1 | không (start 12) |
| 1106 | `admin` → `in&` distance −2 within 3 | gói 1 | **match** (@8, start 10−2) |
| 1107 | `AB` → `XY` distance 1 within 2 | gói 2 | **match**: `AB`@0 thất bại, quay lại `AB`@3 → `XY`@6 |
| 1108 | `AB` → `XY` distance 0 within 2 | gói 2 | không |

Thực tế: gói 1 → 1101, 1103, 1104, 1106; gói 2 → 1107. Với `max_backtrack=1` rule 1107 không match (hết ngân sách), `=2` thì match. **Kết luận: PASS**
