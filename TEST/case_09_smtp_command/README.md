# Case 09 — SMTP command (HELO/EHLO, MAIL FROM, RCPT TO)

**Mục tiêu:** nhận diện và parse lệnh SMTP phía client: HELO/EHLO, MAIL FROM, RCPT TO,
nhiều lệnh trong 1 segment (PIPELINING), nội dung thư sau DATA; không ghi credential ra log.

**Input:** `input.pcap` (tạo bằng `generate.py`), client `192.168.1.10:53000` → server `192.168.1.25:25`,
8 segment theo thứ tự một phiên gửi mail.

**Chạy:**
```bash
python TEST/case_09_smtp_command/generate.py
python main.py --pcap TEST/case_09_smtp_command/input.pcap -o TEST/case_09_smtp_command/output.jsonl
```

## Kết quả

| # | Payload gửi | `detected_by` | `app_data` chính | `error` |
|---|---|---|---|---|
| 1 | `HELO client.uit.local` | `payload` | `type: command`, `helo: "client.uit.local"` | `null` |
| 2 | `EHLO client.uit.local` | `payload` | `helo: "client.uit.local"` | `null` |
| 3 | `AUTH PLAIN AHRoaW5o...` | `payload` | `auth_mechanism: "PLAIN"`, argument `"PLAIN [redacted]"` | `null` |
| 4 | `MAIL FROM:<thinh@uit.edu.vn> SIZE=512` | `payload` | `mail_from: "thinh@uit.edu.vn"`, `mail_params: "SIZE=512"` | `null` |
| 5 | `RCPT TO:<giangvien@uit.edu.vn>` | `payload` | `rcpt_to: ["giangvien@uit.edu.vn"]` | `null` |
| 6 | `RCPT TO:<ta1@...>` + `RCPT TO:<ta2@...>` + `DATA` | `payload` | `commands`: RCPT, RCPT, DATA; `rcpt_to: ["ta1@uit.edu.vn","ta2@uit.edu.vn"]` | `null` |
| 7 | Nội dung thư (header + body + `.`) | `port` | `type: data`, `subject: "Nop bai tap 1 IDS"`, `from`, `to`, `end_of_data: true` | `null` |
| 8 | `QUIT` | `payload` | `commands: [{command: "QUIT"}]` | `null` |

- Lệnh HELO/EHLO/MAIL FROM/RCPT TO nhận diện theo payload; nội dung thư không có chữ ký
  lệnh nên nhận diện theo port 25 (`detected_by = "port"`).
- Gói 6: 3 lệnh pipelined trong 1 segment đều được tách đúng.
- Gói 3: chuỗi base64 chứa mật khẩu **không xuất hiện** trong `output.jsonl`
  (`grep -c AHRoaW5o output.jsonl` → 0). Case này đã phát hiện lỗi `payload_preview` làm lộ
  credential và được sửa ở commit *Fix payload preview leaking SMTP AUTH credentials*.
- Tóm tắt: `events with error: 0, app protocols: SMTP=8`.

**Kết luận: PASS**
