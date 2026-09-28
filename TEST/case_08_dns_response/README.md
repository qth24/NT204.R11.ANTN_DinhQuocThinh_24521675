# Case 08 — DNS response (≥ 1 answer)

**Mục tiêu:** parse DNS response: rcode, cờ, câu hỏi và các resource record (answers,
authorities) kèm RDATA đã decode; xử lý đúng name compression.

**Input:** `input.pcap` (tạo bằng `generate.py`), resolver `8.8.8.8:53` → client. Các message
được nén bằng `dns_compress()` như server thật (vd answer name = con trỏ `C0 0C` về câu hỏi):

1. `www.uit.edu.vn` A → CNAME + A
2. `gmail.com` MX → 2 bản ghi MX
3. `nosuchdomain.invalid` A → NXDOMAIN, có SOA ở authority section

**Chạy:**
```bash
python TEST/case_08_dns_response/generate.py
python main.py --pcap TEST/case_08_dns_response/input.pcap -o TEST/case_08_dns_response/output.jsonl
```

## Kết quả

| # | `type` | `rcode_name` | `flags` rd / ra | `counts` (q/an/ns/ar) | `error` |
|---|---|---|---|---|---|
| 1 | `response` | `NOERROR` | true / true | 1 / 2 / 0 / 0 | `null` |
| 2 | `response` | `NOERROR` | true / true | 1 / 2 / 0 / 0 | `null` |
| 3 | `response` | `NXDOMAIN` (3) | true / true | 1 / 0 / 1 / 0 | `null` |

Resource record đã decode:

| # | Section | `name` | `type` | `ttl` | `data` |
|---|---|---|---|---|---|
| 1 | answers | `www.uit.edu.vn.` | CNAME | 3600 | `uit.edu.vn.` |
| 1 | answers | `uit.edu.vn.` | A | 300 | `118.69.123.140` |
| 2 | answers | `gmail.com.` | MX | 3600 | `{preference: 5, exchange: gmail-smtp-in.l.google.com.}` |
| 2 | answers | `gmail.com.` | MX | 3600 | `{preference: 10, exchange: alt1.gmail-smtp-in.l.google.com.}` |
| 3 | authorities | `invalid.` | SOA | 900 | `{mname: a.root-servers.net., rname: nstld.verisign-grs.com., serial: 2025092800, ...}` |

- Tên miền dạng nén (con trỏ `0xC0..`) được giải nén đúng, không thiếu nhãn.
- NXDOMAIN có `rcode = 3`, `answers = []` — tín hiệu hữu ích cho IDS (vd phát hiện DGA).
- Tóm tắt: `events with error: 0, app protocols: DNS=3`.

**Kết luận: PASS**
