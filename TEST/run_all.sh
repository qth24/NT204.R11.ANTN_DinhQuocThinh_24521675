#!/usr/bin/env bash
# Re-check every BT1 test case: run the parser in BT1 mode (--bt1-only) on the
# committed input PCAP into a temporary folder and compare with the committed
# output.jsonl. Fields added after a case was recorded (e.g.
# ip_total_length, BT2) are ignored; every recorded field must be identical.
# The BT1 case folders are never modified (PCAPs are not regenerated: run a
# case's generate.py by hand to rebuild its input).
# Usage (from the repository root): bash TEST/run_all.sh
set -euo pipefail
PY="${PYTHON:-python}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

check() {  # check <pcap> <committed output> [extra main.py args...]
    local pcap="$1" expected="$2"
    shift 2
    "$PY" main.py --bt1-only --pcap "$pcap" -o "$TMP/out.jsonl" "$@" 2>/dev/null
    "$PY" - "$expected" "$TMP/out.jsonl" <<'PYEOF'
import json, sys
old = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]
new = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8")]
same = len(old) == len(new) and all({k: n[k] for k in o} == o for o, n in zip(old, new))
print(("  OK   " if same else "  DIFF ") + sys.argv[1])
sys.exit(0 if same else 1)
PYEOF
}

for dir in TEST/case_*/; do
    dir="${dir%/}"
    check "$dir/input.pcap" "$dir/output.jsonl"
done
check TEST/case_11_unknown_protocol/input.pcap \
    TEST/case_11_unknown_protocol/output_skip_unknown.jsonl --skip-unknown
check TEST/case_12_malformed_packet/input_truncated.pcap \
    TEST/case_12_malformed_packet/output_truncated.jsonl
