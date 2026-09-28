# Case 10 — SMTP response (status code)

**Mục tiêu:** parse reply của SMTP server: status code, nhóm status (2xx/3xx/4xx/5xx),
enhanced status code (RFC 3463), reply nhiều dòng và nhiều reply trong 1 segment.

**Input:** `input.pcap` (tạo bằng `generate.py`), server `192.168.1.25:25` → client, 7 segment.

**Chạy:**
```bash
python TEST/case_10_smtp_response/generate.py
python main.py --pcap TEST/case_10_smtp_response/input.pcap -o TEST/case_10_smtp_response/output.jsonl
```

## Kết quả

| # | Reply gửi | `status_code` | `status_class` | `enhanced_status` | `replies` (code × số dòng) | `error` |
|---|---|---|---|---|---|---|
| 1 | `220 mail.uit.edu.vn ESMTP Postfix` | 220 | `positive_completion` | `null` | 220×1 | `null` |
| 2 | `250-mail...` / `250-PIPELINING` / ... / `250 AUTH PLAIN LOGIN` | 250 | `positive_completion` | `null` | 250×5 | `null` |
| 3 | `250 2.1.0 Ok` | 250 | `positive_completion` | `2.1.0` | 250×1 | `null` |
| 4 | `250 2.1.5 Ok` + `250 2.1.5 Ok` + `354 End data...` | 250 | `positive_completion` | `2.1.5` | 250×1, 250×1, 354×1 | `null` |
| 5 | `550 5.1.1 <nobody@...>: Recipient address rejected` | 550 | `permanent_negative` | `5.1.1` | 550×1 | `null` |
| 6 | `421 4.7.0 Too many connections...` | 421 | `transient_negative` | `4.7.0` | 421×1 | `null` |
| 7 | `221 2.0.0 Bye` | 221 | `positive_completion` | `2.0.0` | 221×1 | `null` |

- Mọi gói `app_protocol = "SMTP"`, `detected_by = "payload"` (dòng `3 chữ số + dấu cách/-` ở port 25).
- Gói 2: 5 dòng `250-...`/`250 ...` được gom thành **1 reply** với 5 dòng (dấu `-` = còn tiếp).
- Gói 4: 3 reply pipelined trong 1 segment được tách riêng; `status_code` lấy theo reply đầu tiên.
- `status_class` và `enhanced_status` cho phép IDS phát hiện vd dò user (`550 5.1.1` lặp lại).
- Tóm tắt: `events with error: 0, app protocols: SMTP=7`.

**Kết luận: PASS**
