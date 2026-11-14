# Case 06 — Rule Indexer

**Mục tiêu:** `RuleRepository.candidates(event)` trả đúng tập rule: loại rule khác protocol / port chắc chắn không khớp, không sót rule có thể match, không trùng lặp, thứ tự theo file.

**Input:** `index.rules` (7 rule: tcp 80, tcp 1:1024, tcp any, udp 53, udp any, tcp `<>` 8080, tcp 443 từ 10/8), `input_events.jsonl` (7 gói).

**Chạy:** `bash TEST/run_bt3.sh 06` · Test: `pytest tests/bt3/test_case06_indexer.py` · Kết quả: `report.json` → `candidates`.

| Gói | Mô tả | Candidates (thực tế) |
|---|---|---|
| 1 | TCP → 80 | 601, 602, 603 |
| 2 | TCP → 443 | 602, 603, 607 |
| 3 | TCP → 8080 | 603, 606 |
| 4 | TCP 8080 → 5000 (chiều đảo) | 603, 606 (`<>` được tra theo cả src port) |
| 5 | UDP → 53 | 604, 605 |
| 6 | UDP → 9999 | 605 |
| 7 | TCP không có port | 603 |

Kiểm thêm: candidates ⊇ tập rule thật sự pass header matcher (với mọi gói); protocol lạ → `[]`. **Kết luận: PASS**
