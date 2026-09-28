# Case 07 — DNS query

**Mục tiêu:** nhận diện và parse DNS query: transaction id, cờ, câu hỏi (tên miền, QTYPE, QCLASS).

**Input:** `input.pcap` (tạo bằng `generate.py`), client `192.168.1.10` → resolver `8.8.8.8`:

| # | Port đích | Tên miền | QTYPE |
|---|---|---|---|
| 1 | 53 | `uit.edu.vn` | A |
| 2 | 53 | `www.google.com` | AAAA |
| 3 | 53 | `gmail.com` | MX |
| 4 | **5300** | `internal.corp` | TXT |

**Chạy:**
```bash
python TEST/case_07_dns_query/generate.py
python main.py --pcap TEST/case_07_dns_query/input.pcap -o TEST/case_07_dns_query/output.jsonl
```

## Kết quả

| # | `protocol` | `app_protocol` | `detected_by` | `id` | `type` | `questions` | `flags.rd` | `error` |
|---|---|---|---|---|---|---|---|---|
| 1 | UDP | DNS | `port` | 6699 (0x1A2B) | `query` | `uit.edu.vn.` A IN | `true` | `null` |
| 2 | UDP | DNS | `port` | 6700 | `query` | `www.google.com.` AAAA IN | `true` | `null` |
| 3 | UDP | DNS | `port` | 6701 | `query` | `gmail.com.` MX IN | `true` | `null` |
| 4 | UDP | DNS | `payload` | 6702 | `query` | `internal.corp.` TXT IN | `true` | `null` |

- Mọi query: `opcode = "QUERY"`, `counts = {questions: 1, answers: 0, ...}`, `answers = []`.
- Gói 1–3 (port 53): header DNS hợp lệ + port DNS → `detected_by = "port"`.
- Gói 4 (port 5300): không phải port DNS nhưng câu hỏi decode trọn vẹn (kiểm tra chặt) →
  `detected_by = "payload"`.
- Tóm tắt: `events with error: 0, app protocols: DNS=4`.

**Kết luận: PASS**
