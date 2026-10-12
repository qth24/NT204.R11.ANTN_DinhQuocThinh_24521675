# T04 — Invalid bytes

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): 6 payload chứa byte không phải UTF-8 hợp lệ + 1 request hợp lệ ở cuối.

**Chạy:** `bash TEST/run_bt2.sh T04` · Test: `pytest tests/bt2/test_t04_invalid_bytes.py`

| # | Trường hợp | Kết quả thực tế | `decode_status` |
|---|---|---|---|
| 1 | HTTP `text/plain` (không khai báo charset) có byte `\xe1 \xff \xfe` | byte lỗi → `�`, lỗi `invalid UTF-8 at byte 2; undecodable bytes replaced` | `partial` |
| 2 | HTTP `text/html; charset=iso-8859-1` | dùng charset khai báo → `<p>Café crème</p>` (không mất dữ liệu) | `partial` |
| 3 | `GET /caf%E9?name=%FF%FE` | `/caf�?name=��`, raw URI giữ nguyên | `partial` |
| 4 | POST form có byte `\xff\xfe` thô | `form_params = {name: [Thịnh], city: [��HCM]}` | `partial` |
| 5 | `charset=no-such-charset` | lỗi `unknown declared charset`, fallback replace | `partial` |
| 6 | SMTP base64 khai báo `utf-8` nhưng chứa byte latin-1 | `caf�` | `partial` |
| 7 | `GET /still-ok%21` hợp lệ | `/still-ok!` — chương trình vẫn chạy tiếp | `ok` |

- Thứ tự decode charset: UTF-8 strict → charset khai báo → UTF-8 `errors="replace"`; mọi fallback đều `partial` và có lý do trong `decode_errors`.
- Preprocessor đánh dấu 6 event đầu `preprocess_status = partial`, `reason = ["decode_partial"]`; không exception, exit code 0.

**Kết luận: PASS**
