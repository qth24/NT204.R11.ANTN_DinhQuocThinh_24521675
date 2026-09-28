# Case 06 — HTTP response (status + header)

**Mục tiêu:** parse HTTP response: version, status code, reason phrase, header, body.

**Input:** `input.pcap` (tạo bằng `generate.py`), server `93.184.216.34:80` → client:
1. `HTTP/1.1 200 OK` với 5 header (có 2 dòng `Set-Cookie`) + body HTML 43 byte
2. `HTTP/1.1 404 Not Found`
3. `HTTP/1.0 301 Moved Permanently` với header `Location`

**Chạy:**
```bash
python TEST/case_06_http_response/generate.py
python main.py --pcap TEST/case_06_http_response/input.pcap -o TEST/case_06_http_response/output.jsonl
```

## Kết quả

| Field | Gói 1 | Gói 2 | Gói 3 |
|---|---|---|---|
| `app_protocol` / `detected_by` | `HTTP` / `payload` | `HTTP` / `payload` | `HTTP` / `payload` |
| `app_data.type` | `response` | `response` | `response` |
| `version` | `HTTP/1.1` | `HTTP/1.1` | `HTTP/1.0` |
| `status_code` | 200 | 404 | 301 |
| `reason` | `OK` | `Not Found` | `Moved Permanently` |
| `server` | `nginx/1.24.0` | `Apache/2.4.58` | `null` |
| `content_type` | `text/html; charset=utf-8` | `null` | `null` |
| `content_length` | 43 | 0 | `null` |
| `headers` | 5 header, `Set-Cookie` = `"session=abc123; HttpOnly, theme=dark"` | 2 header | `Location: https://example.com/` |
| `body` | `<html><body><h1>Xin chao</h1></body></html>` | `""` | `""` |
| `error` | `null` | `null` | `null` |

- `status_code` là số nguyên, dùng trực tiếp cho luật IDS (vd đếm 404 để phát hiện dò quét thư mục).
- Header lặp lại (`Set-Cookie`) được gộp bằng `", "`, không bị mất.
- Tóm tắt: `events with error: 0, app protocols: HTTP=3`.

**Kết luận: PASS**
