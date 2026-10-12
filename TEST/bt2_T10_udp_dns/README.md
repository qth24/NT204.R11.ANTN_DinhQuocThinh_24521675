# T10 — UDP query / response

**Input:** `input.pcap` (tạo bởi `tests/gen_pcaps_bt2.py`): DNS query `uit.edu.vn A` từ `192.168.1.10:53530` tới `8.8.8.8:53`, response sau 25 ms với 1 answer.

**Chạy:** `bash TEST/run_bt2.sh T10` · Test: `pytest tests/bt2/test_t10_udp_dns.py`

| Gói | Nguồn | IP total length | `direction` | `flow_id` |
|---|---|---|---|---|
| query | 192.168.1.10:53530 | 56 (= 20 IP + 8 UDP + 28 DNS) | forward | `UDP-1601c177d560-1` |
| response | 8.8.8.8:53 | 82 | backward | `UDP-1601c177d560-1` |

`flows.jsonl` — **1 UDP flow**: `application_protocol = DNS`, `state = ACTIVE` (UDP không có state TCP), `packet_count = 2`, `byte_count = 138`, `fwd = 1 gói / 56 B`, `bwd = 1 gói / 82 B`, mọi flag counter = 0, `duration = 0.025 s`.

**Kết luận: PASS**
