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
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
    collector: Callable[[str], dict[str, Any]] = collect_report,
) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = collector(args.target)
    except (DomainValidationError, OSError, ValueError) as exc:
        stderr.write(f"error: {exc}\n")
        return 2
    json.dump(report, stdout, indent=2, sort_keys=True)
    stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
