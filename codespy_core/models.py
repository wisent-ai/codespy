"""Severities, categories, findings, and the scan result reports are written from."""

from collections import Counter
from dataclasses import dataclass, field
from enum import Enum

from .configuration import __version__


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def __lt__(self, other):
        order = [self.INFO, self.LOW, self.MEDIUM, self.HIGH, self.CRITICAL]
        return order.index(self) < order.index(other)

    def __le__(self, other):
        return self == other or self < other


class Category(Enum):
    SECURITY = "security"
    SECRET = "secret"
    INJECTION = "injection"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    DEPRECATION = "deprecation"
    CONFIGURATION = "configuration"
    SUPPLY_CHAIN = "supply-chain"


@dataclass
class Finding:
    rule_id: str
    title: str
    description: str
    severity: Severity
    category: Category
    file_path: str
    line_number: int
    line_content: str
    suggestion: str = ""
    cwe_id: str = ""
    confidence: str = "high"  # high, medium, low

    def to_dict(self):
        d = {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "line_content": self.line_content.strip(),
            "suggestion": self.suggestion,
            "confidence": self.confidence,
        }
        if self.cwe_id:
            d["cwe_id"] = self.cwe_id
        return d

    def to_sarif_result(self):
        """Convert to SARIF result format."""
        result = {
            "ruleId": self.rule_id,
            "level": self._sarif_level(),
            "message": {"text": self.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": self.file_path},
                    "region": {"startLine": self.line_number}
                }
            }],
        }
        if self.suggestion:
            result["fixes"] = [{
                "description": {"text": self.suggestion},
            }]
        return result

    def _sarif_level(self):
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping[self.severity]


@dataclass
class ScanResult:
    path: str
    files_scanned: int = 0
    files_skipped: int = 0
    lines_scanned: int = 0
    scan_duration_ms: float = 0
    findings: list = field(default_factory=list)
    language_stats: dict = field(default_factory=dict)

    @property
    def finding_count(self):
        return len(self.findings)

    @property
    def severity_counts(self):
        counts = Counter()
        for f in self.findings:
            counts[f.severity.value] += 1
        return dict(counts)

    @property
    def category_counts(self):
        counts = Counter()
        for f in self.findings:
            counts[f.category.value] += 1
        return dict(counts)

    def to_dict(self):
        return {
            "version": __version__,
            "path": self.path,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "lines_scanned": self.lines_scanned,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "total_findings": self.finding_count,
            "severity_counts": self.severity_counts,
            "category_counts": self.category_counts,
            "language_stats": self.language_stats,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_sarif(self):
        """Generate SARIF 2.1.0 output for CI/CD integration."""
        rules = {}
        results = []
        for f in self.findings:
            if f.rule_id not in rules:
                rules[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.description},
                    "defaultConfiguration": {"level": f._sarif_level()},
                }
                if f.cwe_id:
                    rules[f.rule_id]["properties"] = {"cwe": f.cwe_id}
            results.append(f.to_sarif_result())

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "codespy",
                        "version": __version__,
                        "informationUri": "https://github.com/wisent-ai/codespy",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }]
        }
