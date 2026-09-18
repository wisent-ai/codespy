"""The scanner-local score and grade summarising one set of findings."""

from ..models import ScanResult, Severity

# A clean codebase scores the top score; each finding takes its severity's deduction off it.
TOP_SCORE = 100
DEDUCTION_BY_SEVERITY = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 10,
    Severity.MEDIUM: 5,
    Severity.LOW: 2,
    Severity.INFO: 0,
}
# Larger codebases get some leniency: one size unit per this many scanned lines,
# and each unit softens the deduction by this fraction.
LINES_PER_SIZE_UNIT = 1000
LENIENCY_PER_SIZE_UNIT = 0.1
# The lowest score that still earns each letter grade, best first; anything below the last is an F.
GRADE_FLOORS = (
    (95, "A+"),
    (90, "A"),
    (80, "B+"),
    (70, "B"),
    (60, "C"),
    (50, "D"),
)
FAILING_GRADE = "F"


def compute_score(result: ScanResult) -> int:
    """Compute a security score (0-100) from findings."""
    if result.files_scanned == 0:
        return TOP_SCORE

    total_deduction = sum(DEDUCTION_BY_SEVERITY[f.severity] for f in result.findings)

    size_factor = max(1, result.lines_scanned / LINES_PER_SIZE_UNIT)
    adjusted_deduction = total_deduction / (1 + size_factor * LENIENCY_PER_SIZE_UNIT)

    return max(0, min(TOP_SCORE, round(TOP_SCORE - adjusted_deduction)))


def score_to_grade(score: int) -> str:
    """Convert score to letter grade."""
    for floor, grade in GRADE_FLOORS:
        if score >= floor:
            return grade
    return FAILING_GRADE
