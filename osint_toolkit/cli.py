"""Command-line interface for the OSINT toolkit."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence
from typing import Any, TextIO

from .collector import collect_report
from .core import DomainValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="osint-toolkit",
        description="Collect bounded, passive OSINT metadata for a public domain.",
    )
    parser.add_argument("target", help="Public domain or HTTPS URL")
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=8.0,
        help="Operation deadline in seconds (default: 8.0)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Path to write JSON report output (default: stdout)",
    )
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    collector: Callable[..., dict[str, Any]] = collect_report,
) -> int:
    args = build_parser().parse_args(argv)
    if args.timeout <= 0:
        stderr.write("error: timeout must be positive\n")
        return 2
    try:
        try:
            report = collector(args.target, timeout=args.timeout)
        except TypeError:
            report = collector(args.target)
    except (DomainValidationError, OSError, ValueError) as exc:
        stderr.write(f"error: {exc}\n")
        return 2

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as file:
                json.dump(report, file, indent=2, sort_keys=True)
                file.write("\n")
        except OSError as exc:
            stderr.write(f"error: failed to write output file: {exc}\n")
            return 2
    else:
        json.dump(report, stdout, indent=2, sort_keys=True)
        stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
