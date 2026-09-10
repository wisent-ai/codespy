"""The scanner-local score and grade summarising one set of findings."""

from ..models import ScanResult, Severity


def compute_score(result: ScanResult) -> int:
    """Compute a security score (0-100) from findings."""
    if result.files_scanned == 0:
        return 100

    # Deductions per severity
    deductions = {
        Severity.CRITICAL: 20,
        Severity.HIGH: 10,
        Severity.MEDIUM: 5,
        Severity.LOW: 2,
        Severity.INFO: 0,
    }

    total_deduction = sum(deductions[f.severity] for f in result.findings)

    # Normalize by codebase size (larger codebases get some leniency)
    size_factor = max(1, result.lines_scanned / 1000)
    adjusted_deduction = total_deduction / (1 + size_factor * 0.1)

    return max(0, min(100, round(100 - adjusted_deduction)))


def score_to_grade(score: int) -> str:
    """Convert score to letter grade."""
    if score >= 95:
        return "A+"
    elif score >= 90:
        return "A"
    elif score >= 80:
        return "B+"
    elif score >= 70:
        return "B"
    elif score >= 60:
        return "C"
    elif score >= 50:
        return "D"
    else:
        return "F"
