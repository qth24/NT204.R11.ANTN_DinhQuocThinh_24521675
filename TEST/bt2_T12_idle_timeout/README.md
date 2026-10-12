# T12 — Idle timeout

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`). Không dùng `sleep`: khoảng cách timestamp giữa các gói lớn hơn timeout. Config mặc định: `udp_idle_timeout = 60`, `tcp_idle_timeout = 300`.

| Gói | t (s) | Nội dung |
|---|---|---|
| 1 | 0 | DNS query UDP `192.168.1.10:53600 → 8.8.8.8:53` |
| 2–4 | 0–0.2 | TCP handshake `192.168.1.10:51600 → .20:80` |
| 5 | 30 | SYN `192.168.1.30:51601 → .20:443` |
| 6 | 61 | SYN lặp lại của flow trên |
| 7 | 90 | DNS query **cùng 5-tuple** với gói 1 |
| 8 | 400 | SYN `192.168.1.30:51601 → :443` |

**Chạy:** `bash TEST/run_bt2.sh T12` · Test: `pytest tests/bt2/test_t12_idle_timeout.py`

**Bảng active sau từng gói** (test `test_t12_active_table_after_each_packet`):

| Sau gói | t | Flow đã export | Flow active | Giải thích |
|---|---|---|---|---|
| 5 | 30 | 0 | 3 | chưa flow nào quá timeout |
| 6 | 61 | 1 | 2 | UDP idle 61 s > 60 s → **export + xóa khỏi bảng** (`EXPIRED`, `idle_timeout`) |
| 7 | 90 | 1 | 3 | cùng 5-tuple UDP → flow **mới** `UDP-9f1b858f4c3a-2` |
| 8 | 400 | 4 | 1 | TCP idle 399.8 s, flow :443 idle 339 s (> 300) và UDP#2 idle 310 s (> 60) bị export; SYN mới → `TCP-ae00395e33a0-2` |

`flows.jsonl` (đúng thứ tự export): `UDP-…-1` (idle_timeout) → `TCP-b3b8…-1` (idle_timeout, ESTABLISHED) → `TCP-ae00…-1` (idle_timeout) → `UDP-…-2` (idle_timeout) → `TCP-ae00…-2` (end_of_capture).

**Kết luận: PASS**
