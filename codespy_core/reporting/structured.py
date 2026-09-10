"""JSON and SARIF reports for other tools to read."""

import json

from ..models import ScanResult


def format_json(result: ScanResult) -> str:
    """Format scan results as JSON."""
    return json.dumps(result.to_dict(), indent=2)


def format_sarif(result: ScanResult) -> str:
    """Format scan results as SARIF 2.1.0."""
    return json.dumps(result.to_sarif(), indent=2)
