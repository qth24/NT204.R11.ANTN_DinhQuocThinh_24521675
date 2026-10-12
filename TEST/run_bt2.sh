#!/usr/bin/env bash
# Build the BT2 test inputs and run the full pipeline on each of them.
# Writes events.jsonl + flows.jsonl into every TEST/bt2_TXX_<name>/ folder.
# Usage (from the repository root): bash TEST/run_bt2.sh [T01 T07 ...]
set -euo pipefail
PY="${PYTHON:-python}"

"$PY" tests/gen_pcaps_bt2.py "$@" >/dev/null

run() {  # run <case id> <output suffix> [extra main.py args...]
    local id="$1" suffix="$2"
    shift 2
    local dir
    dir="$(ls -d TEST/bt2_"${id}"_*)"
    local input=(--pcap "$dir/input.pcap")
    [ -f "$dir/input_events.jsonl" ] && input=(--events "$dir/input_events.jsonl")
    echo "== $dir${suffix:+ ($suffix)}"
    "$PY" main.py "${input[@]}" -o "$dir/events${suffix}.jsonl" \
        --flow-output "$dir/flows${suffix}.jsonl" "$@" 2>&1 | sed 's/^/   /'
}

cases=("$@")
[ ${#cases[@]} -eq 0 ] && cases=(T01 T02 T03 T04 T05 T06 T07 T08 T09 T10 T11 T12 T13 T14)
for id in "${cases[@]}"; do
    run "$id" ""
    if [ "$id" = "T14" ]; then
        # Same input with the "drop" policy for invalid and unsupported events
        run T14 "_drop" --set preprocess.on_invalid=drop --set preprocess.on_unsupported=drop
    fi
done
