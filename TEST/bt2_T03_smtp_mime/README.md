# T03 — SMTP Base64 / Quoted-Printable

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): 5 email (phần sau lệnh `DATA`) gửi tới port 25.

**Chạy:** `bash TEST/run_bt2.sh T03` · Test: `pytest tests/bt2/test_t03_smtp_mime.py`

| # | Content-Transfer-Encoding | Mong đợi | Thực tế (`decoded.mime_parts`) | `decode_status` |
|---|---|---|---|---|
| 1 | `base64` (xuống dòng giữa chừng) | `Chào thầy, em gửi bài tập 2 IDS.` | đúng | `ok` |
| 2 | `quoted-printable` (`=3D`, soft line break `=\r\n`) | `Chào thầy, 1 + 1 = 2 và dòng này rất dài.` | đúng | `ok` |
| 3 | multipart: QP text + base64 PDF **thiếu padding `=`** | text `Bài nộp kèm file.`; PDF không chuyển thành text (`body: null`, `size: 20`) | đúng | `ok` |
| 4 | `base64` nhưng nội dung không phải base64 | `failed`, giữ nguyên text gốc, ghi lỗi | `invalid base64: Only base64 data is allowed` | `failed` |
| 5 | không có (mặc định `7bit`) | không decode → `not_applicable` | đúng | `not_applicable` |

- Trước khi parse MIME, decoder bỏ dòng kết thúc `.` và bỏ dot-stuffing (`..` → `.`) của SMTP.
- Mỗi part có `decode_status` riêng; `decode_status` của event tổng hợp từ các part.

**Kết luận: PASS**
