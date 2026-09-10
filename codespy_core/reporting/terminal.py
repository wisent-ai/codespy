"""Human-readable terminal report, with optional colour."""

from collections import defaultdict

from ..configuration import __version__
from ..models import ScanResult
from .scoring import compute_score, score_to_grade


SEVERITY_COLORS = {
    "critical": "\033[1;31m",  # Bold Red
    "high": "\033[31m",        # Red
    "medium": "\033[33m",      # Yellow
    "low": "\033[36m",         # Cyan
    "info": "\033[37m",        # White/Gray
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def format_terminal(result: ScanResult, show_fix: bool = False, use_color: bool = True) -> str:
    """Format scan results for terminal output."""
    lines = []
    c = SEVERITY_COLORS if use_color else {k: "" for k in SEVERITY_COLORS}
    r = RESET if use_color else ""
    b = BOLD if use_color else ""
    d = DIM if use_color else ""

    # Header
    lines.append(f"\n{b}codespy v{__version__}{r} — Code Security Scanner")
    lines.append(f"{d}{'─' * 60}{r}")
    lines.append(f"  Path:    {result.path}")
    lines.append(f"  Files:   {result.files_scanned} scanned, {result.files_skipped} skipped")
    lines.append(f"  Lines:   {result.lines_scanned:,}")
    lines.append(f"  Time:    {result.scan_duration_ms:.0f}ms")
    lines.append("")

    # Language breakdown
    if result.language_stats:
        lines.append(f"{b}Languages:{r}")
        for lang, stats in sorted(result.language_stats.items(),
                                   key=lambda x: x[1]["lines"], reverse=True):
            lines.append(f"  {lang:15s} {stats['files']:4d} files  {stats['lines']:>8,} lines")
        lines.append("")

    # Summary
    sc = result.severity_counts
    lines.append(f"{b}Findings:{r} {result.finding_count} total")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sc.get(sev, 0)
        if count > 0:
            lines.append(f"  {c[sev]}{sev.upper():10s}{r} {count}")
    lines.append("")

    if not result.findings:
        lines.append(f"  {b}No issues found.{r} Your code looks clean!")
        lines.append("")
        return "\n".join(lines)

    # Findings grouped by file
    lines.append(f"{d}{'─' * 60}{r}")
    findings_by_file = defaultdict(list)
    for f in result.findings:
        findings_by_file[f.file_path].append(f)

    for file_path, file_findings in sorted(findings_by_file.items()):
        lines.append(f"\n{b}{file_path}{r}")
        for f in file_findings:
            sev_str = f"{c[f.severity.value]}{f.severity.value.upper():8s}{r}"
            lines.append(f"  {sev_str}  L{f.line_number:<5d} [{f.rule_id}] {f.title}")
            lines.append(f"           {d}{f.line_content.strip()[:80]}{r}")
            if show_fix and f.suggestion:
                lines.append(f"           💡 {f.suggestion}")

    lines.append(f"\n{d}{'─' * 60}{r}")

    # Score
    score = compute_score(result)
    grade = score_to_grade(score)
    grade_color = c.get("info", "")
    if grade in ("A", "A+"):
        grade_color = "\033[32m" if use_color else ""
    elif grade in ("B", "B+"):
        grade_color = "\033[36m" if use_color else ""
    elif grade in ("C",):
        grade_color = "\033[33m" if use_color else ""
    else:
        grade_color = "\033[31m" if use_color else ""

    lines.append(f"\n{b}Security Score: {grade_color}{score}/100 (Grade: {grade}){r}")
    lines.append("")

    return "\n".join(lines)
