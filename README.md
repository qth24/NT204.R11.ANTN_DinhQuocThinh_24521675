# IDS Packet Capture & Parser

Bài tập 1 môn **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập**: module thu thập traffic (live hoặc từ PCAP), parse qua các layer IPv4 → TCP/UDP → HTTP/DNS/SMTP và xuất ra **Normalized IDS Event** dạng JSON Lines.

- **Sinh viên:** Đinh Quốc Thịnh
- **MSSV:** 24521675

## Cài đặt

Yêu cầu Python 3.10+ (thư viện chính: Scapy).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Chạy chương trình

```bash
# Đọc file PCAP/PCAPNG
python main.py --pcap test.pcap --output output.jsonl

# Bắt live (cần root), có thể lọc BPF, giới hạn số gói / thời gian
sudo .venv/bin/python main.py --interface eth0 --filter "tcp port 80" --count 100
sudo .venv/bin/python main.py --interface eth0 --timeout 30 --skip-unknown
```

| Tham số | Ý nghĩa |
|---|---|
| `-i/--interface`, `-r/--pcap` | Nguồn dữ liệu (bắt buộc chọn 1) |
| `-o/--output` | File JSON Lines (mặc định `output.jsonl`, `-` = stdout); `--append` để ghi nối |
| `-f/--filter`, `-c/--count`, `-t/--timeout` | BPF filter; dừng sau N gói / N giây (live) |
| `--skip-unknown` | Bỏ qua gói protocol không hỗ trợ thay vì ghi event `UNKNOWN` |
| `-v/--verbose` | Log lỗi parse của từng gói ra stderr |

Khi kết thúc, chương trình in thống kê (số gói, số event, số lỗi, phân bố protocol) ra stderr. File PCAP không tồn tại / sai định dạng hoặc thiếu quyền bắt live → in thông báo lỗi, exit code 1.

## Cấu trúc thư mục

```
.
├── main.py              # CLI entrypoint: --interface, --pcap
├── capture/             # live capture + đọc PCAP → RawPacket
├── parsers/
│   ├── network.py       # link layer + IPv4
│   ├── transport.py     # TCP / UDP
│   ├── app_detector.py  # nhận diện application protocol
│   └── app/             # HTTP, DNS, SMTP parser
├── core/                # IDSEvent, Pipeline, JsonLinesWriter
├── tests/               # unit test (pytest)
└── TEST/                # 12 test case chấm điểm (PCAP + output)
```

## Kiến trúc

```
Raw Packet → Network Parser (IPv4) → Transport Parser (TCP/UDP)
→ Application Protocol Detector → Application Protocol Parser
→ Normalized IDS Event → JSON Lines log
```

### Capture layer (`capture/`)

Cả hai nguồn đều trả về iterator các `RawPacket` giống nhau (`timestamp`, `data`, `linktype`, `wire_len`, `truncated`, `source`), nên phía sau chỉ cần **một pipeline**:

| Hàm | Mô tả |
|---|---|
| `read_pcap(path)` | Đọc file `.pcap`/`.pcapng` bằng `scapy.utils.RawPcapReader`. File hỏng/cụt giữa chừng: trả các gói đọc được, log cảnh báo, không crash. |
| `live_packets(interface, bpf_filter, count, timeout)` | Bắt live bằng `scapy.AsyncSniffer` (thread nền → queue → generator). Cần quyền root. |

Lỗi không mở được nguồn (file không tồn tại, không phải PCAP, thiếu quyền, interface sai) được báo bằng `CaptureError`.

### Network parser (`parsers/network.py`)

`parse_network(data, linktype) -> NetworkLayer`, không bao giờ raise:

1. **Bóc header link layer** theo linktype: Ethernet (1, bỏ qua VLAN 802.1Q), raw IP (12/101/228), Linux cooked SLL (113), SLL2 (276), BSD loopback (0).
2. **Parse IPv4 header** (RFC 791) bằng `struct`: version, IHL, total length, id, flags (DF/MF), fragment offset, TTL, protocol, src/dst IP, kiểm tra checksum.
3. `payload` được cắt theo `total_length` (loại bỏ Ethernet padding) để giao cho transport parser.

Gói không phải IPv4 (ARP, IPv6...), header cụt, version/IHL sai, total length sai đều được ghi vào `error` thay vì làm crash chương trình.

### Transport parser (`parsers/transport.py`)

`parse_transport(protocol, data, fragment_offset) -> TransportLayer`, không bao giờ raise:

- **TCP** (proto 6): src/dst port, seq, ack, window, data offset (độ dài header kể cả options), cờ `FIN/SYN/RST/PSH/ACK/URG/ECE/CWR/NS`; payload = phần sau header.
- **UDP** (proto 17): src/dst port, length; payload cắt theo field length.
- Protocol khác (ICMP, GRE...) → `protocol = "UNKNOWN"`. Fragment IP không phải fragment đầu → không có header transport, ghi `error`.
- Header cụt, data offset / UDP length sai → ghi vào `error`, vẫn giữ port nếu đọc được.

### Application protocol detector (`parsers/app_detector.py`)

`detect_app_protocol(transport, src_port, dst_port, payload) -> AppDetection(app_protocol, detected_by)`, kết hợp **payload-based** (ưu tiên) và **port-based** (dự phòng):

| Protocol | Nhận diện theo payload | Port |
|---|---|---|
| HTTP | Dòng đầu `GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH <target> [HTTP/1.x]` hoặc `HTTP/1.x <3 chữ số>` | Dự phòng: 80, 8000, 8008, 8080, 8888 (TCP) |
| SMTP | `HELO/EHLO`, `MAIL FROM:`, `RCPT TO:`, greeting `220 ... ESMTP` ở mọi port; `DATA/QUIT/...` và reply `250 ...` chỉ khi ở port SMTP (vì FTP/POP3 dùng định dạng giống vậy) | Dự phòng: 25, 587, 2525 (TCP) |
| DNS | Ở port 53/5353: header 12 byte hợp lệ (opcode, ≥ 1 record) — message sai định dạng vẫn được đưa cho parser để báo lỗi. Ở port khác: số record phải khớp độ dài và decode được đúng 1 câu hỏi. DNS qua TCP có tiền tố độ dài 2 byte | 53, 5353 |

Payload rỗng (vd TCP handshake) hoặc không khớp → `app_protocol = null`.

### Application parsers (`parsers/app/`)

Mọi parser trả về `AppResult(data, error)`: `data` là dict JSON-serializable (thành `app_data` của event), `error` ghi lỗi parse thay vì raise.

**HTTP** (`http_parser.py`, `parse_http(payload)`):

- Tách header/body tại dòng trống `\r\n\r\n` (chấp nhận cả `\n\n`).
- Request line → `method`, `uri`, `version`; status line → `version`, `status_code`, `reason`.
- Header decode ISO-8859-1 (không bao giờ lỗi), tra cứu không phân biệt hoa thường, header lặp lại được nối bằng `, `. Trích riêng `host`, `user_agent`, `server`, `content_type`, `content_length`.
- Body decode UTF-8 `errors="replace"`, giữ tối đa 1024 ký tự; `body_truncated = true` khi phần body còn lại nằm ở các TCP segment sau.
- Segment giữa message (không có start line) → `type: "continuation"`.

**DNS** (`dns_parser.py`, `parse_dns(payload, tcp=False)`):

- Header 12 byte: `id`, query/response (bit QR), `opcode`, `rcode` + tên (`NXDOMAIN`...), cờ `aa/tc/rd/ra`, số lượng record từng section.
- Question (`name`, `type`, `class`) và resource record của 3 section answers / authorities / additionals (`name`, `type`, `class`, `ttl`, `data`).
- Decode RDATA: A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, OPT (EDNS); type khác → hex.
- Hỗ trợ name compression (con trỏ `0xC0`), giới hạn 20 lần nhảy để chống vòng lặp, kiểm tra biên mọi lần đọc. Label nhị phân hiển thị dạng `\xNN`.
- Message cụt / số record khai báo sai → giữ phần đã parse, ghi `error`.
- `tcp=True` bỏ 2 byte độ dài ở đầu (DNS qua TCP).

**SMTP** (`smtp_parser.py`, `parse_smtp(payload)`), phân loại theo dòng đầu tiên:

- **command**: parse mọi dòng (hỗ trợ PIPELINING) → `commands` [{command, argument}], `helo`, `mail_from`, `rcpt_to` (list), `auth_mechanism`. Credential của `AUTH` bị che (`[redacted]`), không ghi vào log.
- **response**: `status_code`, `status_class` (2xx/3xx/4xx/5xx), `enhanced_status` (RFC 3463, vd `5.1.1`), `message`; gom reply nhiều dòng (`250-...` → `250 ...`) và nhiều reply trong 1 segment vào `replies`.
- **data**: nội dung email sau `DATA` → `subject`, `from`, `to`, `length`, `end_of_data` (gặp `<CRLF>.<CRLF>`), `preview`.
- Lệnh sai cú pháp/không biết, reply code không hợp lệ → vẫn ghi nhận, báo trong `error`.

### Pipeline (`core/pipeline.py`)

`Pipeline(skip_unknown=False)` dùng chung cho live và PCAP:

- `process(raw) -> IDSEvent | None`: gán `packet_id` (bộ đếm tăng dần), rồi gọi lần lượt network → transport → app detector → app parser. **Mỗi layer có try/except riêng**: layer lỗi thì các field của layer trước vẫn giữ, lỗi ghi vào `error` dạng `"<layer>: <mô tả>"`, chương trình không dừng.
- Gói không thuộc protocol hỗ trợ → `protocol = "UNKNOWN"`; nếu `skip_unknown=True` thì bỏ qua.
- `run(source, sink) -> PipelineStats`: chạy trên mọi `RawPacket` của nguồn, đẩy event cho `sink` (vd `JsonLinesWriter.write`), trả thống kê theo protocol.

### Normalized IDS Event (`core/event.py`)

`IDSEvent` (dataclass, `to_dict()` → JSON) là đầu ra duy nhất mà các bài IDS sau đọc — không chứa object Scapy:

| Field | Ý nghĩa |
|---|---|
| `packet_id`, `timestamp` | Số thứ tự gói (từ 1), thời điểm bắt (epoch giây) |
| `src_ip`, `dst_ip` | Địa chỉ IPv4 |
| `protocol` | `TCP` / `UDP` / `UNKNOWN` |
| `src_port`, `dst_port`, `tcp_flags` | Port, cờ TCP (vd `["SYN", "ACK"]`) |
| `app_protocol`, `app_data` | `HTTP` / `DNS` / `SMTP` / `null` và dữ liệu đã parse |
| `error` | Lỗi của mọi layer, dạng `"network: ...; http: ..."`, `null` nếu sạch |
| `length`, `ip_protocol`, `ttl`, `tcp_seq`, `tcp_ack`, `tcp_window`, `payload_length`, `detected_by`, `source` | Thông tin bổ sung |
| `payload_preview` | 128 byte đầu của payload **không thuộc HTTP/DNS/SMTP** (byte không in được hiển thị `\xNN`); `null` khi đã parse vào `app_data`, tránh lộ dữ liệu nhạy cảm như credential SMTP AUTH |

### JSON Lines logger (`core/logger.py`)

`JsonLinesWriter(path, append=False)` (context manager): mỗi event là 1 dòng JSON (`ensure_ascii=False`, giữ nguyên tiếng Việt), `flush()` sau mỗi dòng để theo dõi live bằng `tail -f` và không mất dữ liệu khi Ctrl+C. `path="-"` ghi ra stdout.

## Test case

12 test case trong [`TEST/`](TEST/README.md) (TCP handshake, TCP payload, UDP, HTTP GET/POST/response, DNS query/response, SMTP command/response, unknown protocol, malformed packet). Mỗi case gồm script tạo PCAP bằng Scapy, file PCAP, output JSON Lines và bảng so sánh kết quả mong đợi / thực tế. Chạy lại toàn bộ:

```bash
bash TEST/run_all.sh
```

## Unit test

```bash
python -m pytest tests
```

## AI Usage

- **Công cụ:** Claude Code (Claude Opus).
- **Mục đích:** hỗ trợ thiết kế kiến trúc, sinh code, viết unit test, tạo PCAP mẫu cho test case và rà soát lỗi.
- **Phần code có dùng AI:** `capture/`, `parsers/`, `core/`, `main.py`, `tests/` và các script `TEST/*/generate.py`, `TEST/run_all.sh`.
- Sinh viên đã đọc, chạy kiểm thử và giải thích được toàn bộ code nộp.
