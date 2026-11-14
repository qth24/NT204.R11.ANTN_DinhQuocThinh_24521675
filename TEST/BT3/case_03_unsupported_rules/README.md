# Case 03 — Keyword / rule ngoài phạm vi

**Mục tiêu:** cú pháp đúng nhưng ngoài phạm vi đề → `unsupported` + reason; không crash, không ảnh hưởng rule khác. Keyword vô hại (`reference`, `metadata`, `gid`) được chấp nhận và bỏ qua kèm warning (cấu hình `engine.ignorable_keywords`).

**Input:** `unsupported.rules` (10 rule) + `input_events.jsonl` (1 gói `GET /admin`).

**Chạy:** `bash TEST/run_bt3.sh 03` · Test: `pytest tests/bt3/test_case03_unsupported_rules.py`

| Dòng | Rule | Reason |
|---|---|---|
| 1 | `pcre` | `unsupported:keyword:pcre` |
| 2 | `byte_test` | `unsupported:keyword:byte_test` |
| 3 | `http_uri` | `unsupported:keyword:http_uri` |
| 4 | action `drop` | `unsupported:action:drop` |
| 5 | protocol `icmp` | `unsupported:protocol:icmp` |
| 6 | `!10.0.0.0/8` | `unsupported:ip_syntax:!10.0.0.0/8` |
| 7 | `[80,443]` | `unsupported:port_syntax:[80,443]` |
| 8 | `$HOME_NET` | `unsupported:ip_syntax:$HOME_NET` |
| 9 | `flowbits` | `unsupported:keyword:flowbits` |
| 10 | có `reference/metadata/gid` | **valid**, 3 warning `ignored:keyword:...` |

Kết quả: `loaded=10 valid=1 invalid=0 unsupported=9`; sid 310 vẫn match gói `GET /admin`. Thứ tự quyết định: `invalid` thắng `unsupported` (test `invalid_beats_unsupported`).

**Kết luận: PASS**
