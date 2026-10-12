"""
    n8nleaks [PATH ...]            scan files and folders (default: here)
    n8nleaks --list-rules          what it looks for

Exit codes: 0 nothing at or above --fail-on, 1 something was found,
2 bad arguments or config.
"""

import argparse
import sys
from pathlib import Path

from . import __version__
from . import rules as R
from .config import ConfigError, check_rule_ids, load
from .report import WRITERS
from .scan import scan_paths


def parser():
    p = argparse.ArgumentParser(
        prog="n8nleaks",
        description="Find secrets and personal data in exported n8n workflows.",
        epilog="Settings can also live in .n8nleaks.toml or [tool.n8nleaks] in pyproject.toml.",
    )
    p.add_argument("paths", nargs="*", default=["."], metavar="PATH",
                   help="workflow files or folders to scan (default: .)")
    p.add_argument("--format", choices=sorted(WRITERS), default="text",
                   help="output format (default: text)")
    p.add_argument("--fail-on", choices=[R.ERROR, R.WARNING],
                   help="lowest severity that makes the exit code 1 (default: error)")
    p.add_argument("--disable", action="append", default=[], metavar="RULE",
                   help="skip a rule; repeat it or separate ids with commas")
    p.add_argument("--config", metavar="FILE", help="read settings from this file")
    p.add_argument("--no-redact", action="store_true",
                   help="print found values in full (keep this out of CI logs)")
    p.add_argument("--list-rules", action="store_true", help="list the rules and exit")
    p.add_argument("--version", action="version", version=f"n8nleaks {__version__}")
    return p


def list_rules(out):
    width = max(len(r) for r in R.RULES)
    for rule in R.RULES.values():
        print(f"{rule.id:<{width}}  {rule.severity:<7}  {rule.summary}", file=out)


def main(argv=None):
    # Node names can hold any character; never crash a scan over printing one.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")

    args = parser().parse_args(argv)
    if args.list_rules:
        list_rules(sys.stdout)
        return 0

    try:
        config = load(args.config)
        if args.fail_on:
            config.fail_on = args.fail_on
        extra = {r.strip() for item in args.disable for r in item.split(",") if r.strip()}
        check_rule_ids(extra, "--disable")
        config.disable |= extra
    except ConfigError as e:
        print(f"n8nleaks: {e}", file=sys.stderr)
        return 2

    paths = [Path(p) for p in args.paths]
    missing = [str(p) for p in paths if not p.exists()]
    if missing:
        print(f"n8nleaks: not found: {', '.join(missing)}", file=sys.stderr)
        return 2

    result = scan_paths(paths, config)
    for shown, reason in result.skipped:
        print(f"n8nleaks: skipped {shown}: {reason}", file=sys.stderr)

    WRITERS[args.format](result, not args.no_redact, sys.stdout)

    threshold = R.SEVERITY_RANK[config.fail_on]
    return 1 if any(R.SEVERITY_RANK[f.severity] >= threshold for f in result.findings) else 0
