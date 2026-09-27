# IDS Packet Capture & Parser

Bài tập 1 môn **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập**: module thu thập
traffic (live hoặc từ PCAP), parse qua các layer IPv4 → TCP/UDP → HTTP/DNS/SMTP và xuất
ra **Normalized IDS Event** dạng JSON Lines.

## Cài đặt

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Kiến trúc

```
Raw Packet → Network Parser (IPv4) → Transport Parser (TCP/UDP)
→ Application Protocol Detector → Application Protocol Parser
→ Normalized IDS Event → JSON Lines log
```

### Capture layer (`capture/`)

Cả hai nguồn đều trả về iterator các `RawPacket` giống nhau (`timestamp`, `data`,
`linktype`, `wire_len`, `truncated`, `source`), nên phía sau chỉ cần **một pipeline**:

| Hàm | Mô tả |
|---|---|
| `read_pcap(path)` | Đọc file `.pcap`/`.pcapng` bằng `scapy.utils.RawPcapReader`. File hỏng/cụt giữa chừng: trả các gói đọc được, log cảnh báo, không crash. |
| `live_packets(interface, bpf_filter, count, timeout)` | Bắt live bằng `scapy.AsyncSniffer` (thread nền → queue → generator). Cần quyền root. |

Lỗi không mở được nguồn (file không tồn tại, không phải PCAP, thiếu quyền, interface
sai) được báo bằng `CaptureError`.

### Network parser (`parsers/network.py`)

`parse_network(data, linktype) -> NetworkLayer`, không bao giờ raise:

1. **Bóc header link layer** theo linktype: Ethernet (1, có bỏ qua VLAN 802.1Q),
   raw IP (12/101/228), Linux cooked SLL (113), SLL2 (276), BSD loopback (0).
2. **Parse IPv4 header** (RFC 791) bằng `struct`: version, IHL, total length, id, flags
   (DF/MF), fragment offset, TTL, protocol, src/dst IP, kiểm tra checksum.
3. `payload` được cắt theo `total_length` (loại bỏ Ethernet padding) để giao cho transport parser.

Gói không phải IPv4 (ARP, IPv6...), header cụt, version/IHL sai, total length sai
đều được ghi vào `error` thay vì làm crash chương trình.

### Transport parser (`parsers/transport.py`)

`parse_transport(protocol, data, fragment_offset) -> TransportLayer`, không bao giờ raise:

- **TCP** (proto 6): src/dst port, seq, ack, window, data offset (độ dài header kể cả
  options), cờ `FIN/SYN/RST/PSH/ACK/URG/ECE/CWR/NS`; payload = phần sau header.
- **UDP** (proto 17): src/dst port, length; payload cắt theo field length.
- Protocol khác (ICMP...) → `protocol="UNKNOWN"`. Fragment IP không phải đầu tiên
  → không có header transport, ghi `error`.
- Header cụt, data offset / UDP length sai → ghi vào `error`, vẫn giữ port nếu đọc được.

### Application protocol detector (`parsers/app_detector.py`)

`detect_app_protocol(transport, src_port, dst_port, payload) -> AppDetection(app_protocol, detected_by)`

Kết hợp **payload-based** (ưu tiên) và **port-based** (dự phòng):

| Protocol | Nhận diện theo payload | Port dự phòng |
|---|---|---|
| HTTP | Dòng đầu `GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH <target> [HTTP/1.x]`, hoặc `HTTP/1.x <3 chữ số>` | 80, 8000, 8008, 8080, 8888 (TCP) |
| SMTP | `HELO/EHLO`, `MAIL FROM:`, `RCPT TO:`, greeting `220 ... ESMTP` ở mọi port; `DATA/QUIT/...` và reply `250 ...` chỉ khi ở port SMTP (vì FTP/POP3 dùng định dạng giống vậy) | 25, 587, 2525 (TCP) |
| DNS | Header 12 byte hợp lệ (opcode, số record khớp độ dài). Ngoài port 53/5353 phải decode được đúng 1 câu hỏi (tên, QTYPE, QCLASS). DNS qua TCP có tiền tố độ dài 2 byte | 53, 5353 |

Payload rỗng (vd TCP handshake) hoặc không khớp → `app_protocol=None` (UNKNOWN).

### Application parsers (`parsers/app/`)

Mọi parser trả về `AppResult(data, error)`: `data` là dict JSON-serializable (thành
`app_data` của event), `error` ghi lỗi parse thay vì raise.

**HTTP** (`http_parser.py`, `parse_http(payload)`):

- Tách header/body tại dòng trống `\r\n\r\n` (chấp nhận cả `\n\n`).
- Request line → `method`, `uri`, `version`; status line → `version`, `status_code`, `reason`.
- Header decode ISO-8859-1 (không bao giờ lỗi), tra cứu không phân biệt hoa thường,
  header lặp lại được nối bằng `, `. Trích riêng `host`, `user_agent`, `server`,
  `content_type`, `content_length`.
- Body decode UTF-8 `errors="replace"`, chỉ giữ tối đa 1024 ký tự; `body_truncated`
  khi body nằm ở các TCP segment sau.
- Segment giữa message (không có start line) → `type: "continuation"`.

**DNS** (`dns_parser.py`, `parse_dns(payload, tcp=False)`):

- Header 12 byte: `id`, query/response (bit QR), `opcode`, `rcode` + tên (`NXDOMAIN`...),
  cờ `aa/tc/rd/ra`, số lượng record từng section.
- Question (`name`, `type`, `class`) và resource record của 3 section answers /
  authorities / additionals (`name`, `type`, `class`, `ttl`, `data`).
- Decode RDATA: A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, OPT (EDNS); type khác → hex.
- Hỗ trợ name compression (con trỏ `0xC0`), giới hạn 20 lần nhảy để chống vòng lặp,
  kiểm tra biên mọi lần đọc. Label nhị phân hiển thị dạng `\xNN`.
- Message cụt / số record khai báo sai → giữ phần đã parse, ghi `error`.
- `tcp=True` bỏ 2 byte độ dài ở đầu (DNS qua TCP).

**SMTP** (`smtp_parser.py`, `parse_smtp(payload)`), phân loại theo dòng đầu tiên:

- **command**: parse mọi dòng (hỗ trợ PIPELINING) → `commands` [{command, argument}],
  `helo`, `mail_from`, `rcpt_to` (list), `auth_mechanism`. Credential của `AUTH` bị che
  (`[redacted]`), không ghi vào log.
- **response**: `status_code`, `status_class` (2xx/3xx/4xx/5xx), `enhanced_status`
  (RFC 3463, vd `5.1.1`), `message`; gom reply nhiều dòng (`250-...` → `250 ...`) và nhiều
  reply trong 1 segment vào `replies`.
- **data**: nội dung email sau `DATA` → `subject`, `from`, `to`, `length`,
  `end_of_data` (gặp `<CRLF>.<CRLF>`), `preview`.
- Lệnh sai cú pháp/không biết, reply code không hợp lệ → vẫn ghi nhận, báo trong `error`.

### Normalized IDS Event (`core/event.py`)

`IDSEvent` (dataclass, `to_dict()` → JSON) là đầu ra duy nhất mà các bài IDS sau đọc:

| Field | Ý nghĩa |
|---|---|
| `packet_id`, `timestamp` | Số thứ tự gói (từ 1), thời điểm bắt (epoch giây) |
| `src_ip`, `dst_ip` | Địa chỉ IPv4 |
| `protocol` | `TCP` / `UDP` / `UNKNOWN` |
| `src_port`, `dst_port`, `tcp_flags` | Port, cờ TCP (`["SYN","ACK"]`) |
| `app_protocol`, `app_data` | `HTTP`/`DNS`/`SMTP`/`null` và dữ liệu đã parse |
| `error` | Lỗi của mọi layer, dạng `"network: ...; http: ..."`, `null` nếu sạch |
| `length`, `ip_protocol`, `ttl`, `tcp_seq`, `tcp_ack`, `tcp_window`, `payload_length`, `detected_by`, `source` | Thông tin bổ sung |

## Chạy test

```bash
python -m pytest tests
```

## AI Usage

| Công cụ | Mục đích | Phần code |
|---|---|---|
| Claude Code (Claude Opus) | Thiết kế và sinh code module capture, viết unit test | `capture/raw_packet.py`, `capture/pcap_reader.py`, `capture/live_capture.py`, `tests/test_capture.py` |
| Claude Code (Claude Opus) | Sinh code IPv4 parser (bóc link layer, decode header, checksum), viết unit test | `parsers/network.py`, `tests/test_network.py` |
| Claude Code (Claude Opus) | Sinh code TCP/UDP parser (ports, flags, seq/ack, UDP length), viết unit test | `parsers/transport.py`, `tests/test_transport.py` |
| Claude Code (Claude Opus) | Thiết kế luật nhận diện HTTP/SMTP/DNS theo payload + port, viết unit test | `parsers/app_detector.py`, `tests/test_app_detector.py` |
| Claude Code (Claude Opus) | Sinh code HTTP/1.x parser (request/response line, header, body), viết unit test | `parsers/app/__init__.py`, `parsers/app/http_parser.py`, `tests/test_http_parser.py` |
| Claude Code (Claude Opus) | Sinh code DNS parser (header, question, resource record, name compression), viết unit test | `parsers/app/dns_parser.py`, `tests/test_dns_parser.py` |
| Claude Code (Claude Opus) | Sinh code SMTP parser (command, reply nhiều dòng, message data), viết unit test | `parsers/app/smtp_parser.py`, `tests/test_smtp_parser.py` |
| Claude Code (Claude Opus) | Thiết kế schema Normalized IDS Event, viết unit test | `core/event.py`, `tests/test_event.py` |
