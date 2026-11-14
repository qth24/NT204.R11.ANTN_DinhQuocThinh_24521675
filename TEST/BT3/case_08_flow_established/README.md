# Case 08 — `flow:to_server,established` (end-to-end)

**Mục tiêu:** `flow` dùng đúng flow context của Flow Tracker: handshake chưa xong → không established; sau ACK → established; chiều ngược → không match `to_server`.

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt3.py`): `192.168.1.10:51000 → 192.168.1.20:80` — SYN, SYN/ACK, ACK, request `GET /index.html`, response (body chứa chữ `GET`), ACK. `flow.rules`: 801 `to_server,established`, 802 `to_server,not_established`, 803 `<>` `to_client,established`, 804 `to_server,established` + `content:"GET"`.

**Chạy:** `bash TEST/run_bt3.sh 08` · Test: `pytest tests/bt3/test_case08_flow_established.py`

| Gói | Flags / hướng | State sau gói | Detection (thực tế) |
|---|---|---|---|
| 1 | SYN, forward | NEW | 802 |
| 2 | SYN/ACK, backward | HANDSHAKE | — |
| 3 | ACK, forward | ESTABLISHED | 801 (ACK hoàn tất handshake đã tính là established) |
| 4 | PSH/ACK + request, forward | ESTABLISHED | 801, 804 |
| 5 | PSH/ACK + response, backward | ESTABLISHED | 803 (804 không match: chiều `backward`, dù payload có `GET`) |
| 6 | ACK, forward | ESTABLISHED | 801 |

Định nghĩa đã chốt (README chính): TCP `established` = ESTABLISHED hoặc CLOSING; NEW/HANDSHAKE/CLOSED/RESET = not established; UDP `established` = đã thấy ≥ 1 gói chiều ngược; thiếu flow context → rule có `flow:` không match. **Kết luận: PASS**
