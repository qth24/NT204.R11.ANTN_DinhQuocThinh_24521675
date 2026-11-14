# Case 09 — `content` có/không `nocase`

**Mục tiêu:** phân biệt hoa/thường mặc định; `nocase` không phân biệt, chỉ với ký tự ASCII (so khớp trên bytes).

**Input:** `nocase.rules` — 901 `content:"GET /"`, 902 `content:"get /"; nocase`, 903 `content:"|47 45 54|"` (hex = `GET`), 904 `content:"gét"; nocase`; `input_events.jsonl` 4 gói.

**Chạy:** `bash TEST/run_bt3.sh 09` · Test: `pytest tests/bt3/test_case09_content_nocase.py`

| Gói | Payload | Detection (thực tế) | Giải thích |
|---|---|---|---|
| 1 | `GET /index.html` | 901, 902, 903 | khớp cả 3 |
| 2 | `get /index.html` | 902 | chỉ rule nocase; 901 và hex 903 phân biệt hoa/thường |
| 3 | `GÉT /` | — | `É` (C3 89) không bị gập thành `é` (C3 A9) |
| 4 | `GéT /` | 904 | `G`,`T` gập ASCII, `é` giống hệt |

**Kết luận: PASS**
