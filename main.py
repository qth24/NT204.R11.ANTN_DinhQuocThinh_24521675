"""CLI entrypoint: capture packets (live or PCAP) and write IDS events as JSONL.

By default every event goes through the BT2 stages (Decoder, Preprocessor,
Flow Tracker): events are written to --output and finished flows to
--flow-output. ``--bt1-only`` reproduces the plain BT1 output.

Examples:
    sudo python main.py --interface eth0 --filter "tcp port 80"
    python main.py --pcap test.pcap --output events.jsonl \\
        --flow-output flows.jsonl --config config.json
    python main.py --pcap test.pcap --set decoder.max_body_bytes=4096
    python main.py --pcap test.pcap --bt1-only
    python main.py --events events_in.jsonl -o events.jsonl   # BT2 stages only
    python main.py --pcap test.pcap --rules rules/local.rules \\
        --detection-output detections.jsonl                 # BT3 engine
    python main.py --pcap test.pcap --no-detect              # BT2 behaviour
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Iterable, Sequence
from contextlib import ExitStack

from capture import CaptureError, RawPacket, live_packets, read_pcap
from config import ConfigError, load_config
from core.logger import JsonLinesWriter, read_jsonl
from core.pipeline import Pipeline, PipelineStats
from engine.factory import EngineBundle, build_engine


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IDS Packet Capture & Parser: IPv4 / TCP / UDP / HTTP / DNS / "
        "SMTP -> Normalized IDS Event (JSON Lines)"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-i", "--interface", help="capture live from this interface")
    source.add_argument("-r", "--pcap", help="read packets from a .pcap/.pcapng file")
    source.add_argument(
        "-e",
        "--events",
        help="read already-parsed events from a JSON Lines file (BT2 stages only)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="output.jsonl",
        help="JSON Lines output file, '-' for stdout (default: output.jsonl)",
    )
    parser.add_argument(
        "--flow-output",
        default="flows.jsonl",
        help="JSON Lines file for finished flows (default: flows.jsonl)",
    )
    parser.add_argument(
        "--rules",
        action="append",
        default=[],
        metavar="FILE_OR_DIR",
        help="Snort rule file or directory (repeatable); replaces engine.rule_files",
    )
    parser.add_argument(
        "--detection-output",
        default="detections.jsonl",
        help="JSON Lines file for Detection Events (default: detections.jsonl)",
    )
    parser.add_argument(
        "--no-detect",
        action="store_true",
        help="turn the rule engine off (BT2 behaviour)",
    )
    parser.add_argument(
        "--append", action="store_true", help="append to --output / --flow-output"
    )
    parser.add_argument("-f", "--filter", help="BPF filter for live capture")
    parser.add_argument(
        "-c", "--count", type=int, default=0, help="live: stop after N packets"
    )
    parser.add_argument(
        "-t", "--timeout", type=float, help="live: stop after N seconds"
    )
    parser.add_argument(
        "--skip-unknown",
        action="store_true",
        help="do not write events for unsupported protocols (default: UNKNOWN event)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="log every parse error"
    )
    parser.add_argument("--config", help="BT2 config file (.json, or .yaml)")
    parser.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="SECTION.KEY=VALUE",
        help="override one config value, e.g. flow.tcp_idle_timeout=30 (repeatable)",
    )
    parser.add_argument(
        "--bt1-only",
        action="store_true",
        help="skip the BT2 stages and write plain BT1 events",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.INFO if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    # Scapy prints harmless warnings (e.g. "MAC address not found") on import.
    logging.getLogger("scapy").setLevel(logging.ERROR)

    try:
        config = load_config(args.config, args.set)
    except ConfigError as exc:
        print(f"error: config: {exc}", file=sys.stderr)
        return 1

    if args.events and args.bt1_only:
        print("error: --events needs the BT2 stages (drop --bt1-only)", file=sys.stderr)
        return 1

    source: Iterable[RawPacket]
    if args.events:
        source = []  # not used: events are read in run_events below
    elif args.pcap:
        source = read_pcap(args.pcap)
    else:
        source = live_packets(
            args.interface,
            bpf_filter=args.filter,
            count=args.count,
            timeout=args.timeout,
        )

    # BT3 engine: rules are loaded once here, before any packet is processed.
    bundle: EngineBundle | None = None
    use_engine = (
        not args.bt1_only
        and not args.no_detect
        and config.engine.enabled
        and bool(args.rules or config.engine.rule_files)
    )
    if use_engine:
        bundle = build_engine(config.engine, args.rules)

    stats = PipelineStats()
    try:
        with ExitStack() as stack:
            writer = stack.enter_context(
                JsonLinesWriter(
                    args.output,
                    append=args.append,
                    payload_b64=config.engine.log_payload,
                )
            )
            detections = (
                stack.enter_context(
                    JsonLinesWriter(args.detection_output, append=args.append)
                )
                if bundle
                else None
            )
            pipeline = Pipeline(
                skip_unknown=args.skip_unknown,
                config=config,
                engine=bundle,
                detection_sink=detections.write if detections else None,
            )
            if args.bt1_only:
                stats = pipeline.run(source, writer.write)
            else:
                flows = stack.enter_context(
                    JsonLinesWriter(args.flow_output, append=args.append)
                )
                if args.events:
                    stats = pipeline.run_events(
                        read_jsonl(args.events), writer.write, flows.write
                    )
                else:
                    stats = pipeline.run_bt2(source, writer.write, flows.write)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted, events and flows so far are saved", file=sys.stderr)
        return 130

    _print_summary(stats, args.output, None if args.bt1_only else args.flow_output)
    if bundle is not None:
        _print_engine_summary(bundle, stats, args.detection_output)
    return 0


def _print_summary(stats: PipelineStats, output: str, flow_output: str | None) -> None:
    lines = [
        f"packets processed : {stats.processed}",
        f"events written    : {stats.written} -> {output}",
        f"skipped (unknown) : {stats.skipped}",
        f"events with error : {stats.with_error}",
        "protocols         : " + _format_counter(stats.by_protocol),
        "app protocols     : " + _format_counter(stats.by_app_protocol),
    ]
    if stats.by_preprocess_status or stats.dropped:
        lines += [
            "preprocess status : " + _format_counter(stats.by_preprocess_status),
            f"dropped           : {stats.dropped}",
        ]
    if flow_output is not None:
        lines += [
            f"flows exported    : {stats.flows_exported} -> {flow_output}",
            "flow end reasons  : " + _format_counter(stats.flow_end_reasons),
        ]
    print("\n".join(lines), file=sys.stderr)


def _print_engine_summary(
    bundle: EngineBundle, stats: PipelineStats, detection_output: str
) -> None:
    summary = bundle.load.summary
    ev = bundle.evaluator.summary()
    lines = [
        f"rules             : loaded={summary.loaded} valid={summary.valid} "
        f"invalid={summary.invalid} unsupported={summary.unsupported} "
        f"disabled={summary.disabled}",
        f"detections        : {stats.detections} -> {detection_output}",
        f"engine            : events={ev['events_evaluated']} "
        f"candidates/event={ev['candidates_per_event']} "
        f"rejected_by_header={ev['rules_rejected_by_header']} "
        f"matched={ev['rules_matched']} errors={ev['rule_errors']}",
        "rule hits (sid)   : " + _format_counter(ev["hits_by_sid"]),
    ]
    print("\n".join(lines), file=sys.stderr)


def _format_counter(counter: dict[str, int]) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(counter.items())) or "-"


if __name__ == "__main__":
    sys.exit(main())
