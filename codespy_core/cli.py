"""Command-line arguments, output selection, and the scan exit status."""

import argparse
import os
import sys

from .configuration import __version__
from .models import Severity
from .reporting.markdown import format_markdown
from .reporting.structured import format_json, format_sarif
from .reporting.terminal import format_terminal
from .scanner import run_scan


def parse_severity(s: str) -> Severity:
    """Parse severity string to enum."""
    mapping = {
        "info": Severity.INFO,
        "low": Severity.LOW,
        "medium": Severity.MEDIUM,
        "high": Severity.HIGH,
        "critical": Severity.CRITICAL,
    }
    s = s.lower().strip()
    if s in mapping:
        return mapping[s]
    raise ValueError(f"Invalid severity: {s}. Choose from: {', '.join(mapping.keys())}")


def main():
    parser = argparse.ArgumentParser(
        prog="codespy",
        description="Fast offline code security scanner & quality analyzer.",
        epilog="Built by Adam (ADAM) — https://github.com/wisent-ai/codespy",
    )
    parser.add_argument(
        "path", nargs="?", default=".",
        help="Path to scan (file or directory, default: current directory)"
    )
    parser.add_argument(
        "--format", "-f", choices=["terminal", "json", "sarif", "markdown"],
        default="terminal", help="Output format (default: terminal)"
    )
    parser.add_argument(
        "--severity", "-s", default="info",
        help="Minimum severity to report: info, low, medium, high, critical"
    )
    parser.add_argument(
        "--fix", action="store_true",
        help="Show suggested fixes for each finding"
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="Disable colored output"
    )
    parser.add_argument(
        "--output", "-o",
        help="Write output to file instead of stdout"
    )
    parser.add_argument(
        "--version", "-v", action="version",
        version=f"codespy {__version__}"
    )

    args = parser.parse_args()

    # Validate path
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist.", file=sys.stderr)
        sys.exit(1)

    # Parse severity
    try:
        min_severity = parse_severity(args.severity)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Run scan
    result = run_scan(args.path, min_severity=min_severity)

    # Format output
    use_color = not args.no_color and args.format == "terminal" and sys.stdout.isatty()
    if args.format == "json":
        output = format_json(result)
    elif args.format == "sarif":
        output = format_sarif(result)
    elif args.format == "markdown":
        output = format_markdown(result, show_fix=args.fix)
    else:
        output = format_terminal(result, show_fix=args.fix, use_color=use_color)

    # Write output
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Report written to {args.output}")
    else:
        print(output)

    # Exit code: non-zero if critical/high findings
    critical_high = sum(1 for f in result.findings
                        if f.severity in (Severity.CRITICAL, Severity.HIGH))
    sys.exit(1 if critical_high > 0 else 0)
