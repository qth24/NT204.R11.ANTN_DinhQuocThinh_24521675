# Test cases

Mỗi thư mục `case_XX_<tên>/` gồm:

| File | Nội dung |
|---|---|
| `generate.py` | Script Scapy tạo PCAP mẫu (timestamp cố định → tái tạo y hệt) |
| `input.pcap` | PCAP đầu vào |
| `output.jsonl` | Output của `python main.py --pcap input.pcap -o output.jsonl` |
| `README.md` | Mục tiêu, cách chạy, bảng kết quả mong đợi / thực tế, kết luận |

Kiểm tra lại toàn bộ (từ thư mục gốc repo): `bash TEST/run_all.sh` — chạy `main.py --bt1-only` trên từng `input.pcap` và so với `output.jsonl` đã commit (bỏ qua field mới thêm ở BT2 như `ip_total_length`). Muốn sinh lại PCAP của một case: `python TEST/case_XX_.../generate.py`.

## Tổng hợp

| Case | Nội dung | Điểm kiểm tra chính | Kết quả |
|---|---|---|---|
| [01](case_01_tcp_handshake/) | TCP handshake | `tcp_flags` SYN → SYN,ACK → ACK; seq/ack | PASS |
| [02](case_02_tcp_payload/) | TCP có payload | payload text + nhị phân, `payload_preview`, không gán nhầm app | PASS |
| [03](case_03_udp/) | UDP | port, length, `tcp_flags = []`, datagram rỗng | PASS |
| [04](case_04_http_get/) | HTTP GET | method/URI/Host/User-Agent; nhận diện theo payload ở port 8081 | PASS |
| [05](case_05_http_post/) | HTTP POST có body | body, Content-Length, body chia 2 segment | PASS |
| [06](case_06_http_response/) | HTTP response | status 200/404/301, reason, header, body | PASS |
| [07](case_07_dns_query/) | DNS query | id, câu hỏi A/AAAA/MX/TXT; DNS ở port 5300 | PASS |
| [08](case_08_dns_response/) | DNS response | CNAME + A, MX, NXDOMAIN + SOA; name compression | PASS |
| [09](case_09_smtp_command/) | SMTP command | HELO/EHLO, MAIL FROM, RCPT TO, pipelining, DATA; che credential AUTH | PASS |
| [10](case_10_smtp_response/) | SMTP response | status code, nhóm 2xx–5xx, enhanced status, reply nhiều dòng | PASS |
| [11](case_11_unknown_protocol/) | Unknown protocol | ARP/IPv6/LLDP/ICMP/GRE/SSH/NTP → `UNKNOWN`, `--skip-unknown` | PASS |
| [12](case_12_malformed_packet/) | Malformed packet | 14 kiểu lỗi ở mọi layer + PCAP cụt, exit code 0 | PASS |

## Lỗi phát hiện và sửa trong quá trình test

| Case | Lỗi | Commit sửa |
|---|---|---|
| 01 | `.gitignore` bỏ qua mọi file `output.jsonl` → output case 01 chưa được commit | *Fix gitignore dropping test case outputs* |
| 02 | Event không cho thấy nội dung payload khi không thuộc HTTP/DNS/SMTP | *Add payload preview to IDS event* |
| 09 | `payload_preview` làm lộ chuỗi base64 của `AUTH PLAIN` | *Fix payload preview leaking SMTP AUTH credentials* |
| 11 | NTP do Scapy tạo chứa thời gian hiện tại → PCAP không tái tạo được | *Fix nondeterministic NTP timestamps in case 11* |
| 12 | DNS sai định dạng ở port 53 bị detector bỏ qua, không báo lỗi | *Test malformed packet - case 12* |
