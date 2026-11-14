# Case 13 — Một event match ≥ 2 rule (end-to-end)

**Mục tiêu:** trả về **tất cả** rule match, theo thứ tự deterministic (thứ tự file rule, rồi thứ tự dòng); mặc định không dừng ở match đầu tiên.

**Input:** `input.pcap`: handshake + request `GET /a/../b?q=1+UNION+SELECT+x HTTP/1.1` (gói 4). Hai file rule: `a_web.rules` (1301 GET, 1307 `../`, 1305 POST) và `b_attack.rules` (1303 `union`…`select` nocase distance 1 within 10, 1304 `dsize:>0`). `--rules` nhận cả thư mục → nạp theo thứ tự tên file.

**Chạy:** `bash TEST/run_bt3.sh 13` · Test: `pytest tests/bt3/test_case13_multi_match.py`

| Kết quả | Thực tế |
|---|---|
| gói 4 match 4 rule, thứ tự **1301, 1307, 1303, 1304** (thứ tự file, không phải thứ tự sid: 1307 đứng trước 1303) | `detections.jsonl` đúng thứ tự trên |
| 1305 (POST) không match | không xuất hiện |
| gói 1–3 (không payload) không match gì | đúng |
| đảo thứ tự file (`b_attack` trước) → 1303, 1304, 1301, 1307 | đúng (test) |
| `engine.stop_on_first_match=true` → chỉ 1301 | `detections_stop_on_first.jsonl` có 1 dòng |

**Kết luận: PASS**
