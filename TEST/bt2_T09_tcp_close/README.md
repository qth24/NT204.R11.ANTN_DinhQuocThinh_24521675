# T09 — TCP close (FIN / RST)

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`), client `192.168.1.10` → server `192.168.1.20:80`:
1. Kết nối port 51400: handshake, data, đóng bằng FIN/ACK hai phía + ACK cuối (gói 1–9)
2. Kết nối port 51401: SYN bị server trả **RST/ACK** (gói 10–11)
3. Kết nối mới **cùng 5-tuple** với kết nối 1 (port 51400): SYN → SYN/ACK → ACK (gói 12–14)

**Chạy:** `bash TEST/run_bt2.sh T09` · Test: `pytest tests/bt2/test_t09_tcp_close.py`

| Flow | Gói | `state` | `end_reason` | Ghi chú |
|---|---|---|---|---|
| `TCP-7c14fdd8dd6b-1` | 1–9 | `CLOSED` | `fin` | `fin_count = 2`; xuất ra khi SYN mới (gói 12) đến cùng 5-tuple |
| `TCP-9efbedbb5537-1` | 10–11 | `RESET` | `rst` | `rst_count = 1` |
| `TCP-7c14fdd8dd6b-2` | 12–14 | `ESTABLISHED` | `end_of_capture` | cùng hash với flow 1 nhưng **seq = 2** → không trùng ID giữa 2 phiên |

- State machine: FIN từ A → `CLOSING`; FIN từ B → `CLOSED`; ACK cuối vẫn được đếm (flow CLOSED/RESET được giữ `closed_linger = 5s`).
- RST ở bất kỳ trạng thái nào → `RESET`.

**Kết luận: PASS**
