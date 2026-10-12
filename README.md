# IDS — Packet Capture, Decoder & Flow Tracker

Bài tập lớn môn **Hệ thống tìm kiếm, phát hiện và ngăn chặn xâm nhập (IDS/IPS)**, dùng chung một repo cho các bài tập:

- **Bài tập 1 — Packet Capture & Parser:** thu thập traffic (live hoặc PCAP), parse IPv4 → TCP/UDP → HTTP/DNS/SMTP, xuất **Normalized IDS Event**.
- **Bài tập 2 — Decoder, Preprocessor & Flow/Connection Tracker:** giải mã event → kiểm tra/chuẩn hóa → gắn vào **flow hai chiều** có trạng thái và thống kê.

- **Sinh viên:** Đinh Quốc Thịnh
- **MSSV:** 24521675

## Cài đặt

Yêu cầu Python 3.10+ (thư viện ngoài duy nhất: Scapy; decode/normalize chỉ dùng thư viện chuẩn).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Chạy chương trình

```bash
# PCAP: event đã qua Decoder + Preprocessor + Flow Tracker và các flow đã kết thúc
python main.py --pcap test.pcap --output events.jsonl --flow-output flows.jsonl --config config.json

# Bắt live (cần root); Ctrl+C vẫn ghi đủ event và flush các flow còn mở
sudo .venv/bin/python main.py --interface eth0 --filter "tcp port 80"

# Đổi một ngưỡng từ CLI (ưu tiên hơn file config)
python main.py --pcap test.pcap --set flow.tcp_idle_timeout=30 --set preprocess.on_invalid=drop

# Chạy các stage BT2 trên event JSONL có sẵn (không cần packet)
python main.py --events input_events.jsonl -o events.jsonl --flow-output flows.jsonl

# Chỉ chạy BT1 (output giống Bài tập 1)
python main.py --pcap test.pcap --bt1-only --output output.jsonl
```

| Tham số | Ý nghĩa |
|---|---|
| `-i/--interface`, `-r/--pcap`, `-e/--events` | Nguồn dữ liệu (bắt buộc chọn 1): live, file PCAP/PCAPNG, file event JSONL |
| `-o/--output` | Event JSON Lines (mặc định `output.jsonl`, `-` = stdout) |
| `--flow-output` | Flow JSON Lines (mặc định `flows.jsonl`) |
| `--config`, `--set SECTION.KEY=VALUE` | File config (`.json`; `.yaml` nếu có PyYAML) và ghi đè từng giá trị |
| `--bt1-only` | Bỏ qua các stage BT2, xuất event như Bài tập 1 |
| `-f/--filter`, `-c/--count`, `-t/--timeout` | BPF filter; dừng sau N gói / N giây (live) |
| `--skip-unknown`, `--append`, `-v/--verbose` | Bỏ gói protocol không hỗ trợ; ghi nối file; log lỗi từng gói |

Khi kết thúc, chương trình in thống kê ra stderr (số gói/event, lỗi, phân bố protocol, `preprocess_status`, số event bị drop, số flow và `end_reason`). Lỗi nguồn dữ liệu hoặc config sai → thông báo lỗi, exit code 1.

## Cấu hình (`config.json`)

Mọi ngưỡng đều cấu hình được; thứ tự ưu tiên: giá trị mặc định (`config.py`) < file `--config` < `--set`. Thời gian luôn tính theo **timestamp của packet** (không dùng đồng hồ hệ thống) nên chạy lại PCAP cho kết quả giống hệt.

| Key | Mặc định | Ý nghĩa |
|---|---|---|
| `decoder.enabled` | `true` | Bật/tắt Decoder |
| `decoder.max_body_bytes` | `65536` | Body/MIME part dài hơn bị cắt trước khi decode → `partial`, `truncated_for_decode` |
| `preprocess.enabled` | `true` | Bật/tắt Preprocessor |
| `preprocess.on_invalid` / `on_unsupported` | `mark` | `mark` (giữ, đánh dấu) hoặc `drop` (không vào Flow Tracker) |
| `preprocess.log_dropped` | `true` | Vẫn ghi event bị drop ra `events.jsonl` |
| `flow.enabled` | `true` | Bật/tắt Flow Tracker |
| `flow.tcp_idle_timeout` / `udp_idle_timeout` | `300` / `60` | Giây không có gói → flow hết hạn |
| `flow.closed_linger` | `5` | Giữ flow CLOSED/RESET thêm để nhận ACK cuối |
| `flow.max_active_flows` | `100000` | Bảng flow đầy → evict flow lâu nhất không có gói |
| `flow.portless` | `skip` | Gói không có port (ICMP...): `skip` = không tạo flow, `zero` = dùng port 0 |
| `flow.sweep_interval` | `1` | Khoảng thời gian (packet time) tối thiểu giữa hai lần quét timeout |

## Cấu trúc thư mục

```
.
├── main.py              # CLI: --interface / --pcap / --events
├── config.py, config.json
├── capture/             # BT1: live capture + đọc PCAP → RawPacket
├── parsers/             # BT1: IPv4, TCP/UDP, app detector, HTTP/DNS/SMTP parser
├── core/                # IDSEvent, Pipeline (BT1 + BT2 stages), JSONL reader/writer
├── decoder/             # BT2: charset, URL/form, HTML entity, SMTP MIME
├── preprocess/          # BT2: validator, normalizer
├── flow/                # BT2: flow key, Flow, TCP state machine, FlowTracker
├── tests/               # unit test (pytest); tests/bt2/ + tests/gen_pcaps_bt2.py
└── TEST/                # test case chấm điểm: case_XX_* (BT1), bt2_TXX_* (BT2)
```

## Kiến trúc

```
Raw Packet → Network Parser (IPv4) → Transport Parser (TCP/UDP)
→ Application Protocol Detector → Application Protocol Parser
→ Normalized IDS Event                                   (Bài tập 1)
→ Decoder → Preprocessor → Flow/Connection Tracker       (Bài tập 2)
→ events.jsonl + flows.jsonl
```

Live capture và PCAP dùng **một pipeline duy nhất** (`core/pipeline.py`). Các stage BT2 chỉ làm việc trên event dạng dict, không import Scapy hay đụng raw packet; field gốc không bị ghi đè, kết quả ghi vào field mới. Mỗi stage có `try/except` riêng, lỗi ghi vào `decode_status` / `preprocess_status` / `reason`.

## Bài tập 1 — Packet Capture & Parser

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
| `ip_total_length` | Field *total length* của IPv4 (thêm ở BT2, dùng làm `byte_count` của flow) |
| `payload_preview` | 128 byte đầu của payload **không thuộc HTTP/DNS/SMTP** (byte không in được hiển thị `\xNN`); `null` khi đã parse vào `app_data`, tránh lộ dữ liệu nhạy cảm như credential SMTP AUTH |

### JSON Lines logger (`core/logger.py`)

`JsonLinesWriter(path, append=False)` (context manager): mỗi event là 1 dòng JSON (`ensure_ascii=False`, giữ nguyên tiếng Việt), `flush()` sau mỗi dòng để theo dõi live bằng `tail -f` và không mất dữ liệu khi Ctrl+C. `path="-"` ghi ra stdout.

## Bài tập 2 — Decoder, Preprocessor & Flow Tracker

### Decoder (`decoder/`)

`decode_event(event, cfg, payload)` thêm `decoded`, `decode_status` (`ok` / `partial` / `failed` / `not_applicable`), `decode_errors`. Mỗi lớp encoding chỉ decode **một lần**; nếu sau đó vẫn còn `%XX` hoặc entity HTML thì đánh dấu `double_encoded: true` thay vì decode tiếp.

| Module | Việc làm |
|---|---|
| `charset.py` | bytes → str: UTF-8 strict → charset khai báo trong header → UTF-8 `errors="replace"`; mọi fallback là `partial` kèm lý do |
| `url_decoder.py` | Path: `unquote` (`+` giữ nguyên); query và body `x-www-form-urlencoded`: `parse_qs` (`+` = space) → `decoded.uri`, `query_params`, `form_params`; `app_data.uri` gốc giữ nguyên |
| `html_decoder.py` | `html.unescape` cho body/param `text/html`, `text/plain`, form; không áp lên dữ liệu nhị phân |
| `mime_decoder.py` | Nội dung SMTP sau `DATA`: bỏ dòng `.` cuối và dot-stuffing, tách MIME part, decode `base64` (tự bổ sung padding thiếu) / `quoted-printable` theo `Content-Transfer-Encoding`; encoding khác → `not_applicable`; mỗi part có `decode_status` riêng |

Decoder nhận thêm byte gốc của payload từ pipeline để decode charset chính xác. Với input `--events` (không có byte gốc), decoder dùng text BT1 đã parse. SMTP chỉ decode **theo từng event** (không ghép email trải nhiều packet).

### Preprocessor (`preprocess/`)

- **Điền field thiếu** cho nhất quán: scalar → `null`, list (`tcp_flags`) → `[]`, dict (`app_data`) → `{}`.
- **Validator** → `preprocess_status`:
  - `invalid`: thiếu/hỏng field cốt lõi (`packet_id`, `timestamp`, `src_ip`, `dst_ip`, `protocol`), IP không parse được, timestamp không phải số hữu hạn ≥ 0, protocol ngoài TCP/UDP;
  - `partial`: port thiếu hoặc ngoài `0–65535`, `tcp_flags` sai kiểu, có `error` từ BT1, decode `partial`/`failed`;
  - `valid`: còn lại. Lý do ghi trong `reason`, vd `missing_field:dst_port`, `invalid_port:70000`.
- **Normalizer** → `normalized` (không ghi đè field gốc): protocol/app_protocol viết hoa; IP dạng chuẩn của `ipaddress`; domain (DNS qname / HTTP Host) viết thường, bỏ dấu `.` cuối và port, IDNA cho tên non-ASCII; tên header HTTP viết thường; `uri_path` từ URI đã decode, gộp `//`, resolve `.`/`..` không vượt `/`; `timestamp_iso` (UTC).
- **Policy** → `processing_action`: `valid` → `pass`, `partial` → `mark`, `invalid` → `preprocess.on_invalid` hoặc `on_unsupported` (`mark`/`drop`). Event `drop` không vào Flow Tracker.

### Flow/Connection Tracker (`flow/`)

- **Flow key** (`flow_key.py`): sắp xếp hai endpoint `(ip, port)` theo (phiên bản IP, IP dạng số, port) → `(PROTO, lo_ip, lo_port, hi_ip, hi_port)`; hai chiều A→B và B→A cho cùng key.
- **`flow_id`** = `"{PROTO}-{sha1(key)[:12]}-{seq}"`: phần hash ổn định qua các lần chạy; `seq` tăng khi cùng 5-tuple mở phiên mới sau khi phiên cũ đã đóng/hết hạn.
- **Endpoint A** = initiator: bên gửi SYN; nếu bắt giữa chừng hoặc UDP thì là nguồn của gói đầu tiên. `direction = forward` nếu gói do A gửi, ngược lại `backward`.
- **TCP state machine** (`tcp_state.py`): `NEW` (SYN từ A) → `HANDSHAKE` (SYN/ACK từ B) → `ESTABLISHED` (ACK từ A, hoặc có data hai chiều) → `CLOSING` (FIN một phía) → `CLOSED` (FIN cả hai phía); `RST` ở bất kỳ trạng thái nào → `RESET`. Gói đầu không phải SYN → `ESTABLISHED` + `notes: ["midstream"]`. SYN mới trên flow `CLOSED`/`RESET` → xuất flow cũ, tạo flow mới. UDP: `ACTIVE` → `EXPIRED`.
- **FlowTracker** (`tracker.py`): bảng flow active nằm trong instance; mỗi gói quét timeout theo timestamp packet; flow hết hạn/đóng/bị evict được **ghi ra `flows.jsonl` và xóa khỏi bảng** (`end_reason`: `idle_timeout`, `fin`, `rst`, `evicted`); kết thúc PCAP hoặc Ctrl+C → `flush()` với `end_reason = end_of_capture`.
- **Thống kê mỗi flow:** `packet_count`, `byte_count`, `fwd_*`/`bwd_*`, `syn/ack/fin/rst_count` (số gói mang cờ), `start_time`, `last_seen`, `duration`, `state`, `end_reason`, `notes`, `application_protocol` (app protocol đầu tiên khác `null`).
- **Định nghĩa `byte_count`:** tổng field IPv4 *total length* (`ip_total_length`) của các gói — gồm IP header + TCP/UDP header + payload, không tính header Ethernet/padding, nên không phụ thuộc kiểu link layer.

### Event sau BT2

Giữ nguyên mọi field BT1, thêm: `decoded`, `decode_status`, `decode_errors`, `preprocess_status`, `processing_action`, `reason`, `normalized`, `flow_id`, `direction`.

## Test case

| Bài | Thư mục | Nội dung | Chạy / kiểm tra |
|---|---|---|---|
| BT1 | [`TEST/case_XX_*`](TEST/README.md) | 12 case: TCP handshake/payload, UDP, HTTP GET/POST/response, DNS query/response, SMTP command/response, unknown, malformed | `bash TEST/run_all.sh` — chạy `--bt1-only` trên PCAP đã commit và so với output BT1 (không ghi đè) |
| BT2 | `TEST/bt2_TXX_*` | 14 case T01–T14 (bảng dưới) | `bash TEST/run_bt2.sh [T01 ...]` — sinh input bằng `tests/gen_pcaps_bt2.py` rồi ghi `events.jsonl` + `flows.jsonl` |

| ID | Nội dung | ID | Nội dung |
|---|---|---|---|
| T01 | HTTP URL decode | T08 | Bidirectional (cùng `flow_id`, direction đúng) |
| T02 | HTML entity | T09 | TCP close: FIN → CLOSED, RST → RESET |
| T03 | SMTP Base64 / QP | T10 | UDP DNS query/response → 1 flow |
| T04 | Byte không hợp lệ | T11 | Nhiều flow đồng thời không gộp nhầm |
| T05 | Normalization | T12 | Idle timeout: export + xóa khỏi bảng |
| T06 | Thiếu field | T13 | Thống kê packet/byte/flag/duration |
| T07 | TCP handshake → ESTABLISHED | T14 | Event sai định dạng, policy mark/drop |

Mỗi thư mục BT2 có input (`input.pcap` hoặc `input_events.jsonl`), output và `README.md` (input, lệnh chạy, mong đợi vs thực tế). Unit test tương ứng: `tests/bt2/test_tXX_*.py` — so sánh giá trị cụ thể và so với output đã commit.

## Unit test

```bash
python -m pytest tests            # toàn bộ (BT1 + BT2 + regression BT1)
python -m pytest tests/bt2 -v     # chỉ BT2
```

## AI Usage

**Bài tập 1**
- **Công cụ:** Claude Code (Claude Opus).
- **Mục đích:** hỗ trợ thiết kế kiến trúc, sinh code, viết unit test, tạo PCAP mẫu và rà soát lỗi.
- **Phần code có dùng AI:** `capture/`, `parsers/`, `core/`, `main.py`, `tests/`, script trong `TEST/case_*`.

**Bài tập 2**
- **Công cụ:** Claude Code (Claude Opus).
- **Mục đích:** hỗ trợ thiết kế Decoder/Preprocessor/Flow Tracker, sinh code, viết test case và script sinh PCAP, rà soát lỗi phát hiện khi test.
- **Phần code có dùng AI:** `config.py`, `decoder/`, `preprocess/`, `flow/`, phần mở rộng trong `core/` và `main.py`, `tests/bt2/`, `tests/gen_pcaps_bt2.py`, script trong `TEST/`.

Sinh viên đã đọc, chạy kiểm thử và giải thích được toàn bộ code nộp.
