# Case 04 — HTTP GET

**Mục tiêu:** nhận diện và parse HTTP GET request: method, URI, version, header (Host,
User-Agent...). Chứng minh detection dựa trên payload, không phụ thuộc tuyệt đối vào port.

**Input:** `input.pcap` (tạo bằng `generate.py`):
1. `GET /index.html?lang=vi` tới `93.184.216.34:80` (port HTTP chuẩn)
2. `GET /api/status` tới port **8081** (không nằm trong danh sách port HTTP)

**Chạy:**
```bash
python TEST/case_04_http_get/generate.py
python main.py --pcap TEST/case_04_http_get/input.pcap -o TEST/case_04_http_get/output.jsonl
```

## Kết quả

| Field | Gói 1 (port 80) | Gói 2 (port 8081) |
|---|---|---|
| `app_protocol` | `HTTP` | `HTTP` |
| `detected_by` | `payload` | `payload` |
| `app_data.type` | `request` | `request` |
| `app_data.method` | `GET` | `GET` |
| `app_data.uri` | `/index.html?lang=vi` | `/api/status` |
| `app_data.version` | `HTTP/1.1` | `HTTP/1.1` |
| `app_data.host` | `example.com` | `internal.local:8081` |
| `app_data.user_agent` | `Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0` | `curl/8.5.0` |
| `app_data.headers` | 4 header (Host, User-Agent, Accept, Connection) | 2 header |
| `app_data.body_length` | 0 | 0 |
| `error` | `null` | `null` |

- Gói 2 ở port 8081 vẫn được nhận diện HTTP nhờ dòng đầu `GET /api/status HTTP/1.1`
  (`detected_by = "payload"`), đúng yêu cầu kết hợp port-based + payload-based.
- Tóm tắt: `events with error: 0, app protocols: HTTP=2`.

**Kết luận: PASS**
