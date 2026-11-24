"""Command line entrypoint."""

from __future__ import annotations

import argparse
import sys
from typing import Sequence

from . import __version__
from .checks import CHECK_IDS, CHECKS, SEVERITIES, SEVERITY_RANK, Options, at_or_above, run
from .loader import InputError, load
from .render import RENDERERS, render

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_INPUT = 2

FAIL_ON = (*SEVERITIES, "none")


def _check_list(value: str) -> set[str]:
    wanted = {item.strip().upper() for item in value.split(",") if item.strip()}
    unknown = sorted(wanted - set(CHECK_IDS))
    if unknown:
        raise argparse.ArgumentTypeError(
            f"unknown check id(s): {', '.join(unknown)}. Known ids: {', '.join(CHECK_IDS)}"
        )
    return wanted


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-msk-cluster-audit",
        description=(
            "Audit Amazon MSK clusters from describe-cluster-v2 / list-clusters-v2 JSON. "
            "Never calls AWS."
        ),
        epilog="Checks: " + ", ".join(f"{c.id} ({c.severity})" for c in CHECKS),
    )
    parser.add_argument(
        "-i", "--input", action="append", metavar="PATH", default=None,
        help="file, directory of .json dumps, or - for stdin (repeatable)",
    )
    parser.add_argument("-f", "--format", choices=sorted(RENDERERS), default="table")
    parser.add_argument(
        "--severity", choices=SEVERITIES, default="low",
        help="only report findings at or above this severity (default: low)",
    )
    parser.add_argument(
        "--fail-on", choices=FAIL_ON, default="medium",
        help="exit 1 when a reported finding is at or above this severity (default: medium)",
    )
    parser.add_argument("--only", type=_check_list, metavar="IDS",
                        help="comma-separated check ids to run exclusively")
    parser.add_argument("--skip", type=_check_list, metavar="IDS",
                        help="comma-separated check ids to skip")
    parser.add_argument("--region", action="append", metavar="REGION",
                        help="audit only these regions (repeatable)")
    parser.add_argument("--cluster", action="append", metavar="NAME",
                        help="audit only these cluster names (repeatable)")
    parser.add_argument("--min-version", metavar="X.Y.Z",
                        help="Kafka versions below this are EOL_KAFKA_VERSION findings")
    parser.add_argument("--require-cmk", action="store_true",
                        help="treat an AWS-managed at-rest key as a finding")
    parser.add_argument("--list-checks", action="store_true",
                        help="print the check table and exit")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _print_checks(stream) -> None:
    width = max(len(c.id) for c in CHECKS)
    print(f"{'CHECK'.ljust(width)}  SEVERITY  APPLIES TO    SUMMARY", file=stream)
    for check in CHECKS:
        applies = "both" if len(check.applies) == 2 else check.applies[0].lower()
        print(f"{check.id.ljust(width)}  {check.severity.ljust(8)}  {applies.ljust(12)}  "
              f"{check.summary}", file=stream)


def main(argv: Sequence[str] | None = None, stdout=None, stderr=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    out = stdout or sys.stdout
    err = stderr or sys.stderr

    if args.list_checks:
        _print_checks(out)
        return EXIT_OK

    if args.only and args.skip and args.only & args.skip:
        overlap = ", ".join(sorted(args.only & args.skip))
        print(f"error: --only and --skip both name {overlap}", file=err)
        return EXIT_INPUT

    inputs = args.input or ["-"]
    try:
        bundle = load(inputs)
    except InputError as exc:
        print(f"error: {exc}", file=err)
        return EXIT_INPUT

    clusters = bundle.clusters
    if args.region:
        wanted = {r.strip() for r in args.region}
        clusters = [c for c in clusters if c.region in wanted]
    if args.cluster:
        names = {n.strip() for n in args.cluster}
        clusters = [c for c in clusters if c.name in names]

    findings = run(
        clusters,
        Options(min_version=args.min_version, require_cmk=args.require_cmk),
        only=args.only,
        skip=args.skip,
    )
    findings = at_or_above(findings, args.severity)
    findings.sort(key=lambda f: (-SEVERITY_RANK[f.severity], f.region, f.cluster, f.check))

    print(render(args.format, findings, clusters), file=out)

    if args.fail_on == "none":
        return EXIT_OK
    return EXIT_FINDINGS if at_or_above(findings, args.fail_on) else EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
