"""Command-line entry point for php2shell-probe."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import List

from . import __version__
from .detector import Result, fingerprint

# Exit codes. EXIT_CONFIRMED is deliberately NOT 2 — argparse itself exits
# with status 2 on a usage/argument error, and a CI pipeline gating on "2
# means confirmed vulnerability" would otherwise also trip on a typo'd
# command line.
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIRMED = 3  # at least one host confirmed vulnerable — useful for CI gating


def _load_targets(path: str) -> List[str]:
    """Load targets from a file, stdin ('-'), or — if the value is itself a
    URL (contains '://') — treat it as a single bare target, so
    `--targets https://example.org` (as shown in the README) works without
    requiring a one-line file. Anything else is always a file path, and a
    missing/unreadable file is a clean CLI error, not an uncaught
    traceback."""
    if path == "-":
        lines = sys.stdin.read().splitlines()
    elif "://" in path:
        return [path.strip()]
    else:
        try:
            lines = Path(path).read_text().splitlines()
        except OSError as exc:
            print(f"could not read targets file {path!r}: {exc}", file=sys.stderr)
            sys.exit(EXIT_ERROR)
    return [line.strip() for line in lines if line.strip() and not line.strip().startswith("#")]


def _write_csv(rows, output: str) -> None:
    fh = sys.stdout if output == "-" else open(output, "w", newline="")
    try:
        writer = csv.writer(fh)
        writer.writerow(["target", "verdict", "php_version", "detail"])
        for r in rows:
            writer.writerow([r.target, r.verdict, r.php_version or "", r.detail])
    finally:
        if fh is not sys.stdout:
            fh.close()


def _write_table(rows) -> None:
    widths = [max(len(str(getattr(r, f))) for r in rows) if rows else 0 for f in ("target", "verdict", "php_version")]
    widths = [max(w, len(h)) for w, h in zip(widths, ("target", "verdict", "php_version"))]
    header = f"{'target':<{widths[0]}}  {'verdict':<{widths[1]}}  {'php_version':<{widths[2]}}  detail"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(f"{r.target:<{widths[0]}}  {r.verdict:<{widths[1]}}  {(r.php_version or ''):<{widths[2]}}  {r.detail}")


def _cmd_scan(args: argparse.Namespace) -> int:
    targets = _load_targets(args.targets)
    if not targets:
        print("no targets loaded", file=sys.stderr)
        return EXIT_ERROR

    if args.active:
        if not args.i_have_authorization:
            print(
                "--active sends a crash-triggering probe and requires --i-have-authorization "
                "as an explicit acknowledgement that you are authorized to actively test every "
                "target in this run.",
                file=sys.stderr,
            )
            return EXIT_ERROR
        from .nuclei_runner import NucleiNotFound, NucleiRunError, run_active_probe  # deferred: only needed for --active

        try:
            active_results = run_active_probe(targets, timeout=args.timeout, confirmed_authorization=True)
        except (NucleiNotFound, NucleiRunError, FileNotFoundError) as exc:
            print(f"active probe failed: {exc}", file=sys.stderr)
            return EXIT_ERROR
        rows = [
            Result(r.target, r.verdict, None, f"{r.cve_id or ''}: {r.detail}".strip(": "))
            for r in active_results
        ]
    else:
        rows = [fingerprint(t, timeout=args.timeout) for t in targets]

    if args.format == "csv":
        _write_csv(rows, args.output)
    else:
        _write_table(rows)

    return EXIT_CONFIRMED if any(r.verdict == "confirmed" for r in rows) else EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="php2shell-probe",
        description="Detection probe for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan one or more targets")
    scan.add_argument(
        "--targets", required=True,
        help="path to a file with one hostname/URL per line, '-' for stdin, "
             "or a single target URL (must contain '://')",
    )
    scan.add_argument("--output", default="-", help="output path for --format csv ('-' for stdout)")
    scan.add_argument("--format", choices=["csv", "table"], default="csv")
    scan.add_argument("--timeout", type=float, default=10.0, help="per-request timeout in seconds")
    scan.add_argument(
        "--active", action="store_true",
        help="send the active crash probe via Nuclei instead of passive version fingerprinting",
    )
    scan.add_argument(
        "--i-have-authorization", action="store_true",
        help="required alongside --active: confirms you are authorized to actively test every target",
    )
    scan.set_defaults(func=_cmd_scan)

    return parser


def main(argv: list = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
