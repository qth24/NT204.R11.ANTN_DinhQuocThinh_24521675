# Case 05 — HTTP POST có body

**Mục tiêu:** parse HTTP POST: method, URI, Content-Type, Content-Length và **body**;
xử lý body bị chia sang nhiều TCP segment.

**Input:** `input.pcap` (tạo bằng `generate.py`), client `192.168.1.10` → server `192.168.1.80:80`:
1. `POST /login` form-urlencoded, body 45 byte nằm trọn trong 1 segment
2. `POST /api/v1/readings` JSON 68 byte — segment đầu chứa header + 38 byte body
3. Segment thứ hai của request 2, chỉ chứa 30 byte body còn lại

**Chạy:**
```bash
python TEST/case_05_http_post/generate.py
python main.py --pcap TEST/case_05_http_post/input.pcap -o TEST/case_05_http_post/output.jsonl
```

## Kết quả

| Field | Gói 1 | Gói 2 | Gói 3 |
|---|---|---|---|
| `app_protocol` / `detected_by` | `HTTP` / `payload` | `HTTP` / `payload` | `HTTP` / `port` |
| `app_data.type` | `request` | `request` | `continuation` |
| `method` / `uri` | `POST` / `/login` | `POST` / `/api/v1/readings` | — |
| `content_type` | `application/x-www-form-urlencoded` | `application/json` | — |
| `content_length` | 45 | 68 | — |
| `body` | `username=admin&password=P%40ssw0rd&remember=1` | `{"device": "sensor-01", "temperature":` | ` 31.5, "note": "phong may B2"}` |
| `body_length` | 45 | 38 | 30 |
| `body_truncated` | `false` | `true` | `false` |
| `error` | `null` | `null` | `null` |

- Gói 1: body khớp `Content-Length` → `body_truncated = false`.
- Gói 2: có 38 < 68 byte → `body_truncated = true`, báo hiệu phần còn lại ở segment sau.
- Gói 3: không có request line nên không khớp chữ ký HTTP; được nhận diện bằng **port 80**
  (`detected_by = "port"`) và parse thành `continuation`. 38 + 30 = 68 = `Content-Length`.
- Tóm tắt: `events with error: 0, app protocols: HTTP=3`.

**Kết luận: PASS**
