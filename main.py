"""CLI entrypoint: capture packets (live or PCAP) and write IDS events as JSONL.

Examples:
    sudo python main.py --interface eth0 --filter "tcp port 80"
    python main.py --pcap test.pcap --output events.jsonl
"""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Iterable, Sequence

from capture import CaptureError, RawPacket, live_packets, read_pcap
from core.logger import JsonLinesWriter
from core.pipeline import Pipeline, PipelineStats


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IDS Packet Capture & Parser: IPv4 / TCP / UDP / HTTP / DNS / "
        "SMTP -> Normalized IDS Event (JSON Lines)"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("-i", "--interface", help="capture live from this interface")
    source.add_argument("-r", "--pcap", help="read packets from a .pcap/.pcapng file")
    parser.add_argument(
        "-o",
        "--output",
        default="output.jsonl",
        help="JSON Lines output file, '-' for stdout (default: output.jsonl)",
    )
    parser.add_argument("--append", action="store_true", help="append to --output")
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

    source: Iterable[RawPacket]
    if args.pcap:
        source = read_pcap(args.pcap)
    else:
        source = live_packets(
            args.interface,
            bpf_filter=args.filter,
            count=args.count,
            timeout=args.timeout,
        )

    pipeline = Pipeline(skip_unknown=args.skip_unknown)
    stats = PipelineStats()
    try:
        with JsonLinesWriter(args.output, append=args.append) as writer:
            stats = pipeline.run(source, writer.write)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\ninterrupted, events so far are saved", file=sys.stderr)
        return 130

    _print_summary(stats, args.output)
    return 0


def _print_summary(stats: PipelineStats, output: str) -> None:
    lines = [
        f"packets processed : {stats.processed}",
        f"events written    : {stats.written} -> {output}",
        f"skipped (unknown) : {stats.skipped}",
        f"events with error : {stats.with_error}",
        "protocols         : " + _format_counter(stats.by_protocol),
        "app protocols     : " + _format_counter(stats.by_app_protocol),
    ]
    print("\n".join(lines), file=sys.stderr)


def _format_counter(counter: dict[str, int]) -> str:
    return ", ".join(f"{k}={v}" for k, v in sorted(counter.items())) or "-"


if __name__ == "__main__":
    sys.exit(main())
