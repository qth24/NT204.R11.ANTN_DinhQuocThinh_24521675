# T06 — Missing field

**Input:** `input_events.jsonl` (tạo bởi `tests/gen_pcaps_bt2.py`): 7 event thiếu các field không bắt buộc ở nhiều mức.

**Chạy:** `bash TEST/run_bt2.sh T06` · Test: `pytest tests/bt2/test_t06_missing_field.py`

**Quy tắc (Preprocessor):** field BT1 bị thiếu được thêm vào với giá trị rỗng theo kiểu — scalar → `null`, list (`tcp_flags`) → `[]`, dict (`app_data`) → `{}`; list/dict bằng `null` cũng coi là thiếu. Giá trị có sẵn (kể cả sai kiểu) được giữ nguyên cho validator báo lỗi.

| # | Input | Kết quả thực tế |
|---|---|---|
| 1 | chỉ 5 field cốt lõi, `protocol: UDP` | `src_port/dst_port/app_protocol/error = null`, `tcp_flags = []`, `app_data = {}`; `partial`, `reason = [missing_field:src_port, missing_field:dst_port]`; không có port → `flow_id = null` |
| 2 | TCP, không port/flags | như #1 |
| 3 | HTTP, `app_data` không có uri/host/headers | `decoded` đủ key với `null`, `normalized.http_headers = {}`, `uri_path = null`; `valid` |
| 4 | HTTP, `app_data: null` | `app_data = {}`, không exception |
| 5 | DNS không có `questions` | `normalized.domain = null` |
| 6 | SMTP `data` không có `preview` | `decoded.body_text = ""`, `decode_status = not_applicable` |
| 7 | event đầy đủ (đối chứng) | `valid`, `pass` |

- Mọi event trong `events.jsonl` có **cùng một tập key**; không có exception, exit code 0.
- Case này phát hiện lỗi field thiếu không được điền (event #1 thiếu hẳn key, #4 giữ `app_data: null`) — sửa ở commit *Fix missing optional fields not filled with defaults*.

**Kết luận: PASS**
