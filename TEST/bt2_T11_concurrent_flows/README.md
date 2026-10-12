# T11 — Concurrent flows

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): 12 gói của 4 flow **xen kẽ nhau**, endpoint gần giống nhau để thử gộp nhầm:

| Flow | Giao thức | Endpoint A → B | Khác flow a ở |
|---|---|---|---|
| a | TCP | 192.168.1.10:**51500** → 192.168.1.20:80 | — |
| b | TCP | 192.168.1.10:**51501** → 192.168.1.20:80 | chỉ khác port nguồn |
| c | TCP | **192.168.1.11**:51500 → 192.168.1.20:80 | chỉ khác IP nguồn |
| dns | **UDP** | 192.168.1.10:51500 → 8.8.8.8:53 | cùng IP+port client, khác protocol |

**Chạy:** `bash TEST/run_bt2.sh T11` · Test: `pytest tests/bt2/test_t11_concurrent_flows.py`

**Kết quả:** 4 flow riêng biệt. Thứ tự gán flow theo gói đúng như trong PCAP: `a, b, c, a, dns, c, b, a, b, c, a, c`.

| Flow | `flow_id` | `packet_count` | `state` |
|---|---|---|---|
| a | `TCP-4df6dd2d12e7-1` | 4 | ESTABLISHED |
| b | `TCP-74751f471199-1` | 3 | ESTABLISHED |
| c | `TCP-ee82c393b3dd-1` | 4 | ESTABLISHED |
| dns | `UDP-90259bd4a42a-1` | 1 | ACTIVE |

- Mỗi flow có state machine riêng: handshake của a, b, c xen kẽ nhưng đều tới ESTABLISHED đúng.

**Kết luận: PASS**
