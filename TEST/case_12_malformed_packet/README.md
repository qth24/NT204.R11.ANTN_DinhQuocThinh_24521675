# Case 12 — Malformed packet (không crash)

**Mục tiêu:** gói sai định dạng ở mọi layer và file PCAP bị cụt không làm crash chương trình;
lỗi được ghi vào field `error` kèm tên layer, các field đọc được vẫn được giữ, và gói hợp lệ
phía sau vẫn được xử lý bình thường.

**Input** (tạo bằng `generate.py`, ghi byte thô bằng `RawPcapWriter` để Scapy không "sửa" gói):
- `input.pcap`: 14 frame lỗi + 1 frame HTTP GET hợp lệ ở cuối.
- `input_truncated.pcap`: capture 3 gói hợp lệ bị cắt 25 byte cuối file (record cuối dở dang).

**Chạy:**
```bash
python TEST/case_12_malformed_packet/generate.py
python main.py --pcap TEST/case_12_malformed_packet/input.pcap -o TEST/case_12_malformed_packet/output.jsonl
python main.py --pcap TEST/case_12_malformed_packet/input_truncated.pcap -o TEST/case_12_malformed_packet/output_truncated.jsonl
```

## Kết quả — `output.jsonl`

| # | Lỗi cố ý | `protocol` | Field vẫn giữ | `error` |
|---|---|---|---|---|
| 1 | Frame rỗng (0 byte) | `UNKNOWN` | — | `network: Link layer: truncated Ethernet header: 0 bytes, need 14` |
| 2 | Ethernet header cụt (10 byte) | `UNKNOWN` | — | `network: Link layer: truncated Ethernet header: 10 bytes, need 14` |
| 3 | IPv4 header cụt (12/20 byte) | `UNKNOWN` | — | `network: Truncated IPv4 header: 12 bytes (need at least 20)` |
| 4 | IP version = 5 | `UNKNOWN` | — | `network: Invalid IP version 5 (expected 4)` |
| 5 | IHL = 3 (header 12 byte) | `UNKNOWN` | — | `network: Invalid IPv4 header length 12` |
| 6 | Total length 1500 > dữ liệu thực | `TCP` | IP, port 51000→80, SYN | `network: Truncated IPv4 packet: total length 1500, only 40 bytes captured` |
| 7 | Total length 10 < header | `TCP` | IP, port | `network: Invalid IPv4 total length 10 (smaller than header length 20)` |
| 8 | TCP header cụt (10/20 byte) | `TCP` | IP | `transport: Truncated TCP header: 10 bytes (need at least 20)` |
| 9 | TCP data offset = 3 | `TCP` | IP, port 51000→80 | `transport: Invalid TCP data offset: header length 12` |
| 10 | UDP length = 4 (< 8) | `UDP` | IP, port 51001→9999 | `transport: Invalid UDP length 4 (smaller than header)` |
| 11 | DNS: con trỏ nén trỏ vào chính nó | `UDP` / DNS | header DNS (id, flags) | `dns: Malformed DNS message: bad compression pointer to offset 12` |
| 12 | DNS: header khai báo 50 answer, có 0 | `UDP` / DNS | question `uit.edu.vn.` | `dns: Malformed DNS message: truncated domain name at offset 28 ...` |
| 13 | HTTP: dòng header không có `:`, `Content-Length: -5`, body không phải UTF-8 | `TCP` / HTTP | method, uri, host, body (ký tự `�`) | `http: Malformed header line: 'this line has no colon'; Invalid Content-Length: '-5'` |
| 14 | SMTP: `MAIL` thiếu `FROM:<>`, `HELO` thiếu domain | `TCP` / SMTP | 2 lệnh vẫn ghi nhận | `smtp: Malformed MAIL FROM: 'thinh@uit.edu.vn'; HELO without domain` |
| 15 | **Gói hợp lệ** `GET /still-working` | `TCP` / HTTP | đầy đủ | `null` |

- Tóm tắt: `packets processed: 15, events written: 15, events with error: 14`, **exit code 0**.
- Gói 11: vòng lặp con trỏ bị chặn (giới hạn 20 lần nhảy) — không treo chương trình.
- Gói 12: ban đầu detector loại gói này khỏi DNS vì số record không khớp độ dài, nên lỗi bị bỏ qua
  lặng lẽ. Đã sửa `parsers/app_detector.py` (cùng commit): trên port DNS chỉ cần header hợp lệ,
  việc kiểm tra số record giao cho DNS parser báo lỗi. Output case 01–11 không thay đổi.

## Kết quả — `output_truncated.jsonl` (PCAP bị cụt)

| # | `app_protocol` | `error` |
|---|---|---|
| 1 | HTTP | `null` |
| 2 | HTTP | `null` |
| 3 | HTTP (header vẫn đọc được) | `capture: truncated packet (79 of 104 bytes); network: Truncated IPv4 packet: total length 90, only 65 bytes captured` |

- Reader in cảnh báo `Truncated record ... expected 104 bytes, got 79`, vẫn trả 3 gói, exit code 0.

**Kết luận: PASS**
