# T02 — HTML entity

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): 6 HTTP response với Content-Type khác nhau + 1 POST form.

**Chạy:** `bash TEST/run_bt2.sh T02` · Test: `pytest tests/bt2/test_t02_html_entity.py`

| # | Content-Type | Body gốc | Mong đợi `decoded.body_text` | Thực tế |
|---|---|---|---|---|
| 1 | `text/html` | `&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;` | `<script>alert('XSS')</script>` | đúng |
| 2 | `text/plain` | `Tom &amp; Jerry &copy; 2025 &#x1F600; &#8364;` | `Tom & Jerry © 2025 😀 €` | đúng |
| 3 | `text/html` | `&amp;lt;script&amp;gt;...` (2 lớp) | decode 1 lớp: `&lt;script&gt;...`, `double_encoded: true` | đúng |
| 4 | `text/html` | `&notanentity; &#99999999; &#xZZ; & alone` | không crash; theo HTML5: `¬anentity; � &#xZZ; & alone` | đúng |
| 5 | `application/json` | `&lt;b&gt;` | không áp HTML decode → giữ `&lt;b&gt;` | đúng |
| 6 | `image/png` | nhị phân chứa `&lt;` | không decode: `body_text = null`, `decode_status = not_applicable` | đúng |
| 7 | POST form | `comment=%26lt%3Bimg...%26gt%3B&name=Th%E1%BB%8Bnh` | `form_params.comment = <img src=x onerror=alert(1)>`, `name = Thịnh` | đúng |

- Thứ tự decode của form: URL decode (`%26lt%3B` → `&lt;`) rồi HTML entity (`&lt;` → `<`), mỗi lớp đúng 1 lần.
- `decode_status`: `ok` cho 1–5 và 7, `not_applicable` cho 6.

**Kết luận: PASS**
