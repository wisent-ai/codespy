"""Maintainability and performance patterns that are not vulnerabilities."""

from ..models import Category, Severity

MAINTAINABILITY = [
    # ── Code Quality ──
    (
        "QUA001", "TODO/FIXME/HACK comment",
        r"""#\s*(?:TODO|FIXME|HACK|XXX|WORKAROUND)\b""",
        Severity.INFO, Category.QUALITY,
        "Technical debt marker found.",
        "Address the TODO/FIXME before merging to main branch.",
        "", None, "high"
    ),
    (
        "QUA002", "Broad exception catch",
        r"""except\s*(?:Exception|BaseException|\s*:)""",
        Severity.LOW, Category.QUALITY,
        "Catching broad exceptions can hide bugs.",
        "Catch specific exceptions (e.g., ValueError, KeyError).",
        "CWE-396", {"python"}, "medium"
    ),
    (
        "QUA003", "Mutable default argument",
        r"""def\s+\w+\(.*=\s*(?:\[\]|\{\}|set\(\))""",
        Severity.MEDIUM, Category.QUALITY,
        "Mutable default argument in function definition. This is a common Python bug.",
        "Use None as default and initialize inside the function: def f(x=None): x = x or []",
        "CWE-665", {"python"}, "high"
    ),
    (
        "QUA004", "Loose equality (==) in JS",
        r"""[^=!<>]==[^=]""",
        Severity.LOW, Category.QUALITY,
        "Loose equality (==) can lead to unexpected type coercion.",
        "Use strict equality (===) instead.",
        "", {"javascript"}, "low"
    ),
    (
        "QUA005", "Console.log in production code",
        r"""console\.log\s*\(""",
        Severity.INFO, Category.QUALITY,
        "console.log() found. Remove before production deployment.",
        "Use a proper logging library or remove debug logging.",
        "", {"javascript", "typescript"}, "medium"
    ),
    (
        "QUA006", "Empty catch block",
        r"""(?:catch\s*\([^)]*\)\s*\{\s*\}|except.*:\s*(?:pass|\.\.\.)\s*$)""",
        Severity.MEDIUM, Category.QUALITY,
        "Empty catch/except block silently swallows errors.",
        "Log the error or handle it explicitly.",
        "CWE-390", None, "medium"
    ),
]

PERFORMANCE = [
    # ── Performance ──
    (
        "PRF001", "Synchronous file I/O in async context",
        r"""(?:async\s+def\s+.*\n(?:.*\n)*?.*(?:open\(|os\.path|shutil\.))|(?:await.*(?:open\(|os\.path))""",
        Severity.LOW, Category.PERFORMANCE,
        "Synchronous file I/O in an async function blocks the event loop.",
        "Use aiofiles or run_in_executor for file I/O in async code.",
        "", {"python"}, "low"
    ),
    (
        "PRF002", "N+1 query pattern",
        r"""for\s+\w+\s+in\s+.*:\s*\n\s*.*(?:\.query|\.execute|\.find|\.get|SELECT)""",
        Severity.MEDIUM, Category.PERFORMANCE,
        "Potential N+1 query pattern: database query inside a loop.",
        "Use batch queries, JOINs, or prefetch_related/select_related.",
        "", None, "low"
    ),
    (
        "PRF003", "Regex in loop without compilation",
        r"""for\s+.*:\s*\n(?:.*\n)*?\s*re\.(?:search|match|findall|sub)\s*\(""",
        Severity.LOW, Category.PERFORMANCE,
        "Regex used inside a loop without pre-compilation.",
        "Compile the regex before the loop: pattern = re.compile(r'...'); pattern.search(text)",
        "", {"python"}, "low"
    ),
]
