# Case 11 — Unknown protocol (không crash)

**Mục tiêu:** gói thuộc protocol không hỗ trợ được đánh dấu `UNKNOWN` (hoặc bỏ qua theo
config `--skip-unknown`), chương trình không crash và vẫn xử lý các gói còn lại.

**Input:** `input.pcap` (tạo bằng `generate.py`), 7 gói không hỗ trợ ở các layer khác nhau:

| # | Gói | Không hỗ trợ ở layer |
|---|---|---|
| 1 | ARP request | Network (EtherType 0x0806) |
| 2 | IPv6 / UDP (DHCPv6) | Network (EtherType 0x86DD) |
| 3 | LLDP | Network (EtherType 0x88CC) |
| 4 | ICMP echo request | Transport (IP proto 1) |
| 5 | GRE tunnel | Transport (IP proto 47) |
| 6 | SSH banner, TCP port 22 | Application |
| 7 | NTP request, UDP port 123 | Application |

**Chạy:**
```bash
python TEST/case_11_unknown_protocol/generate.py
python main.py --pcap TEST/case_11_unknown_protocol/input.pcap -o TEST/case_11_unknown_protocol/output.jsonl
python main.py --pcap TEST/case_11_unknown_protocol/input.pcap -o TEST/case_11_unknown_protocol/output_skip_unknown.jsonl --skip-unknown
```

## Kết quả — chế độ mặc định (`output.jsonl`)

| # | `src_ip` → `dst_ip` | `ip_protocol` | `protocol` | port | `app_protocol` | `error` |
|---|---|---|---|---|---|---|
| 1 | `null` | `null` | `UNKNOWN` | — | `null` | `network: Unsupported network protocol: ARP (0x0806)` |
| 2 | `null` | `null` | `UNKNOWN` | — | `null` | `network: Unsupported network protocol: IPv6 (0x86dd)` |
| 3 | `null` | `null` | `UNKNOWN` | — | `null` | `network: Unsupported network protocol: LLDP (0x88cc)` |
| 4 | 192.168.1.10 → .20 | 1 | `UNKNOWN` | — | `null` | `transport: Unsupported transport protocol: 1` |
| 5 | 192.168.1.10 → .20 | 47 | `UNKNOWN` | — | `null` | `transport: Unsupported transport protocol: 47` |
| 6 | 192.168.1.10 → .20 | 6 | `TCP` | 22 → 51000 | `null` | `null` |
| 7 | 192.168.1.10 → .20 | 17 | `UDP` | 51001 → 123 | `null` | `null` |

- Gói 4–5: layer IPv4 vẫn parse được nên `src_ip`/`dst_ip`/`ip_protocol` được giữ lại.
- Gói 6–7: TCP/UDP hợp lệ nhưng không phải HTTP/DNS/SMTP → `app_protocol = null`, nội dung
  xem ở `payload_preview` (`"SSH-2.0-OpenSSH_9.6\r\n"`, NTP dạng `\xNN`).
- Tóm tắt: `packets processed: 7, events written: 7, protocols: TCP=1, UDP=1, UNKNOWN=5`, exit code 0.

## Kết quả — `--skip-unknown` (`output_skip_unknown.jsonl`)

- Chỉ ghi 2 event (gói 6 và 7, có `protocol` TCP/UDP); 5 gói `UNKNOWN` bị bỏ qua.
- `packet_id` giữ nguyên số thứ tự gốc (6, 7) để đối chiếu với PCAP.
- Tóm tắt: `packets processed: 7, events written: 2, skipped (unknown): 5`, exit code 0.

**Kết luận: PASS**
