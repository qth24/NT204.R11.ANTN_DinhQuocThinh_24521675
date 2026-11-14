# Case 04 — Parse header TCP + IP/CIDR + port/range

**Mục tiêu:** Internal Rule Object đúng từng field.

**Input:** `header.rules` (6 rule) · không cần detection (xem `report.json` → `rules`).

**Chạy:** `bash TEST/run_bt3.sh 04` · Test: `pytest tests/bt3/test_case04_header_parse.py`

| Sid | Header | Kết quả parse |
|---|---|---|
| 401 | `any any -> any any` | `src_nets=dst_nets=()`, `src_ports=dst_ports=()` (rỗng = any) |
| 402 | `192.168.1.10 any -> 10.0.0.5 80` | `192.168.1.10/32`, `10.0.0.5/32`, port đơn = `PortRange(80,80)` |
| 403 | `10.0.0.0/8 1024: -> 192.168.0.0/16 1:1024` | CIDR + `PortRange(1024,65535)`, `PortRange(1,1024)` |
| 404 | `any :1023 <> any 8080` | `PortRange(0,1023)`, direction `<>` |
| 405 | `10.1.2.3/8` | `strict=False` → `10.0.0.0/8` |
| 406 | rule đầy đủ | `content` = `b"a;b: c"` (giải `\;` và `\|3a 20\|`), nocase, offset 2, depth 10; `flow` to_server/established; `flags` `+` {S,A} mask {C,E}; `dsize` range 4–8; classtype `web-attack`; priority 2; sid 406, rev 3 |

`rev` mặc định 1 khi thiếu. **Kết luận: PASS**
