# T05 — Normalization

**Input:** `input_events.jsonl` (event viết tay, tạo bởi `tests/gen_pcaps_bt2.py`) — cùng một thông tin nhưng viết hoa/thường, dấu chấm cuối, port, header name khác kiểu nhau.

**Chạy:** `bash TEST/run_bt2.sh T05` (= `python main.py --events TEST/bt2_T05_normalization/input_events.jsonl -o ... --flow-output ...`) · Test: `pytest tests/bt2/test_t05_normalization.py`

| Field gốc (giữ nguyên) | Giá trị trong `normalized` |
|---|---|
| `protocol`: `tcp`, `Tcp`, `udp`, `UDP` | `TCP`, `TCP`, `UDP`, `UDP` |
| `app_protocol`: `http`, `HTTP`, `dns`, `Dns` | `HTTP`, `HTTP`, `DNS`, `DNS` |
| Host `WWW.Example.COM:8080` và `www.example.com.` | `domain = www.example.com` (cả hai) |
| Header `HOST`, `uSeR-AgEnT: " curl/8.5 "`, `Content-TYPE` | `host`, `user-agent: "curl/8.5"`, `content-type` |
| URI `/a/./b/../../..//admin//panel%2F..%2Fusers?Sort=DESC` | `uri_path = /admin/users` (decode → gộp `//` → resolve `..` không vượt `/`); query giữ riêng ở `decoded.query_params` |
| DNS `WWW.UIT.EDU.VN.` | `www.uit.edu.vn` |
| DNS `Bücher.DE` (non-ASCII) | IDNA: `xn--bcher-kva.de` |
| `dst_ip` `2001:DB8:0:0::1` | `2001:db8::1` |
| `src_ip` ` 192.168.001.010 ` | `null` + `reason = invalid_ip` (số 0 đứng đầu bị từ chối vì có thể hiểu là bát phân) |
| `timestamp` `1759100001.0` | `timestamp_iso = 2025-09-28T22:53:21.000000+00:00` |

- `flows.jsonl`: `application_protocol` cũng đã chuẩn hóa (`HTTP`/`DNS`).
- Case này phát hiện 2 lỗi, đã sửa trước khi ghi kết quả: decoder so sánh `app_protocol` phân biệt hoa thường (event `http` không được decode) và flow lấy `app_protocol` thô (`http`/`Dns`) — commit *Fix case-sensitive app protocol check in decoder*, *Fix flow application protocol case*.

**Kết luận: PASS**
