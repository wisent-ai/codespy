"""Detection rule families. FAMILY_ORDER is the order of the released RULES table.

Rule order is part of what the tool promises: findings of equal severity, file and
line keep it, so reports stay stable between runs. Both the scanner and the
standalone build read this one declaration rather than repeating the sequence.
"""

from importlib import import_module

FAMILY_ORDER = (
    ("secrets", "CREDENTIALS"),
    ("injection", "CODE_EXECUTION"),
    ("configuration", "APPLICATION_SETTINGS"),
    ("quality", "MAINTAINABILITY"),
    ("quality", "PERFORMANCE"),
    ("configuration", "SUPPLY_CHAIN"),
    ("configuration", "CONTAINER_IMAGES"),
    ("configuration", "INFRASTRUCTURE"),
    ("secrets", "SERVICE_TOKENS"),
    ("injection", "REQUEST_FORGERY"),
    ("injection", "REDIRECTS"),
    ("secrets", "TOKEN_VERIFICATION"),
    ("configuration", "CRYPTOGRAPHY"),
    ("injection", "TEMPLATES"),
    ("injection", "BROWSER_MARKUP"),
    ("injection", "WEB_FRAMEWORKS"),
    ("configuration", "JAVASCRIPT_RUNTIME"),
    ("configuration", "PYTHON_RUNTIME"),
    ("injection", "DESERIALIZATION"),
    ("configuration", "KUBERNETES"),
    ("configuration", "CONTAINER_BUILDS"),
    ("configuration", "MANAGED_DATABASES"),
    ("secrets", "LEAKED_VALUES"),
    ("configuration", "REQUEST_HANDLING"),
)


def families() -> list:
    """Each declared family, in released order, as (module name, family name, rules)."""
    found = []
    for module_name, family_name in FAMILY_ORDER:
        module = import_module(f".{module_name}", __name__)
        found.append((module_name, family_name, getattr(module, family_name)))
    return found


RULES = [rule for _, _, family in families() for rule in family]
