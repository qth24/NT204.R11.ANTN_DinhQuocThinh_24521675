#!/usr/bin/env bash
# Build the BT3 test inputs and run the full pipeline with the rules of each case.
# Writes events.jsonl, flows.jsonl, detections.jsonl, run.log and report.json
# into every TEST/BT3/case_XX_<name>/ folder.
# Usage (from the repository root): bash TEST/run_bt3.sh [01 08 ...]
set -euo pipefail
PY="${PYTHON:-python}"

cases=("$@")
[ ${#cases[@]} -eq 0 ] && cases=(01 02 03 04 05 06 07 08 09 10 11 12 13 14)
"$PY" tests/gen_pcaps_bt3.py "${cases[@]}" >/dev/null

for id in "${cases[@]}"; do
    dir="$(ls -d TEST/BT3/case_"${id}"_*)"
    input=(--pcap "$dir/input.pcap")
    [ -f "$dir/input_events.jsonl" ] && input=(--events "$dir/input_events.jsonl")
    echo "== $dir"
    # --rules takes the folder: every *.rules file in it, in name order
    "$PY" main.py "${input[@]}" --rules "$dir" \
        -o "$dir/events.jsonl" --flow-output "$dir/flows.jsonl" \
        --detection-output "$dir/detections.jsonl" 2> "$dir/run.log"
    "$PY" tests/bt3/report.py "$dir"
    if [ "$id" = "13" ]; then
        # Same input, stop at the first matching rule
        "$PY" main.py "${input[@]}" --rules "$dir" \
            -o /dev/null --flow-output /dev/null \
            --detection-output "$dir/detections_stop_on_first.jsonl" \
            --set engine.stop_on_first_match=true 2> /dev/null
    fi
done
