# Case 14 — Detection Event (end-to-end)

**Mục tiêu:** Detection Event đủ `sid/rev/msg/priority/classtype`, 5-tuple, protocol, application_protocol, flow_id, direction, packet_id, `match_info`; tên field cố định cho bài Alert/Logging/Response.

**Input:** `input.pcap`: handshake + request `GET /a/../etc/passwd` (gói 4) + truy vấn DNS `example.com` (UDP, gói 5). `detection.rules`: 1401 (rev 2, priority 1, classtype `web-application-attack`, flow + 2 content), 1402 (DNS, hex content, không có priority).

**Chạy:** `bash TEST/run_bt3.sh 14` · Test: `pytest tests/bt3/test_case14_detection_event.py`

| Field | Detection 1401 (thực tế) | Detection 1402 |
|---|---|---|
| `sid`/`rev`/`msg` | 1401 / 2 / `WEB traversal in GET` | 1402 / 1 / `DNS query example.com` |
| `classtype`/`priority` | `web-application-attack` / 1 | `misc-activity` / `null` |
| 5-tuple | `192.168.1.10:51200 → 192.168.1.20:80` | `192.168.1.10:53000 → 192.168.1.1:53` |
| `protocol`/`application_protocol` | TCP / HTTP | UDP / DNS |
| `flow_id`/`direction` | `TCP-6f0165291f93-1` / forward | `UDP-7d9017766e10-1` / forward |
| `packet_id`, `timestamp` | 4, `1759100000.03` (của gói, không phải giờ máy) | 5, `1759100000.1` |
| `match_info.contents` | `GET ` @0, `../` @7 | pattern hiển thị hex `\|07 65 78 …\|` @12, nocase |
| `match_info.flow` | `to_server`/`established`, state ESTABLISHED | `null` |

Test kiểm tra thứ tự/tên field đúng contract, `flow_id` khớp `flows.jsonl`, `packet_id` khớp `events.jsonl`. **Kết luận: PASS**
