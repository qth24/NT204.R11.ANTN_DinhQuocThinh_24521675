#!/usr/bin/env bash
# Regenerate every test case: build input PCAPs with Scapy, then run the parser.
# Usage (from the repository root): bash TEST/run_all.sh
set -euo pipefail
PY="${PYTHON:-python}"

for dir in TEST/case_*/; do
    dir="${dir%/}"
    echo "== ${dir}"
    "$PY" "$dir/generate.py"
    "$PY" main.py --pcap "$dir/input.pcap" -o "$dir/output.jsonl"
done

# Extra runs
"$PY" main.py --pcap TEST/case_11_unknown_protocol/input.pcap \
    -o TEST/case_11_unknown_protocol/output_skip_unknown.jsonl --skip-unknown
"$PY" main.py --pcap TEST/case_12_malformed_packet/input_truncated.pcap \
    -o TEST/case_12_malformed_packet/output_truncated.jsonl
