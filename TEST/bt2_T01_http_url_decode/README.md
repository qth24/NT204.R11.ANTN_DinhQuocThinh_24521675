# T01 — HTTP URL decode

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): 5 request GET có percent-encoding + 1 POST form.

**Chạy:** `bash TEST/run_bt2.sh T01` (hoặc `python main.py --pcap TEST/bt2_T01_http_url_decode/input.pcap -o TEST/bt2_T01_http_url_decode/events.jsonl --flow-output TEST/bt2_T01_http_url_decode/flows.jsonl`) · Test: `pytest tests/bt2/test_t01_http_url_decode.py`

| # | Raw (`app_data.uri` — giữ nguyên) | Mong đợi `decoded` | Thực tế |
|---|---|---|---|
| 1 | `/search%20page/a+b?q=%3Cscript%3E...&lang=vi+VN&empty=` | path `/search page/a+b` (`+` trong path giữ nguyên), `q=<script>alert(1)</script>`, `lang=vi VN`, `empty=""` | đúng |
| 2 | `/products?id=1%27%20OR%201%3D1--` | `id = 1' OR 1=1--` | đúng |
| 3 | `/%252e%252e/%252e%252e/etc/passwd?f=%2527` | chỉ decode 1 lớp → `/%2e%2e/%2e%2e/etc/passwd?f=%27`, `double_encoded: true` | đúng |
| 4 | `/files/report%2Bfinal%20v2.pdf` | `/files/report+final v2.pdf` | đúng |
| 5 | `http://example.com/a%20b?x=1` (absolute-form) | `/a b?x=1` | đúng |
| 6 | POST body `username=admin%27--&password=P%40ss+word%21` | `form_params = {username: [admin'--], password: [P@ss word!]}` | đúng |

- Mọi event: `decode_status = "ok"`, `preprocess_status = "valid"`; raw URI không bị thay đổi.

**Kết luận: PASS**
