# Case 10 — `offset` / `depth`

**Mục tiêu:** pattern phải nằm **trọn** trong cửa sổ `[offset, offset+depth)`; `depth` tính từ `offset`. Kiểm cả hai phía biên.

**Input:** payload `ABCDEFGHIJ` (A=byte 0 … J=byte 9); `offset_depth.rules` 9 rule.

**Chạy:** `bash TEST/run_bt3.sh 10` · Test: `pytest tests/bt3/test_case10_offset_depth.py`

| Sid | Rule | Cửa sổ | Kết quả |
|---|---|---|---|
| 1001 | `EF` offset 4 depth 2 | [4,6) | **match** @4 (vừa khít) |
| 1002 | `EF` offset 5 depth 5 | [5,10) | không (EF bắt đầu ở 4) |
| 1003 | `EF` offset 3 depth 3 | [3,6) | **match** @4 (kết thúc đúng biên) |
| 1004 | `EF` offset 3 depth 2 | [3,5) | không (thiếu 1 byte) |
| 1005 | `IJ` offset 8 | [8,10) | **match** @8 (sát cuối payload) |
| 1006 | `IJ` offset 9 | [9,10) | không (chỉ còn 1 byte) |
| 1007 | `AB` depth 2 | [0,2) | **match** @0 |
| 1008 | `BC` depth 2 | [0,2) | không |
| 1009 | `BC` depth 3 | [0,3) | **match** @1 |

Thực tế `detections.jsonl`: 1001, 1003, 1005, 1007, 1009 (kèm `match_info.contents[].offset`). **Kết luận: PASS**
