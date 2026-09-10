"""Credential material, service tokens, token verification, and leaked values."""

from ..models import Category, Severity

CREDENTIALS = [
    # ── Hardcoded Secrets ──
    (
        "SEC001", "Hardcoded password",
        r"""(?:password|passwd|pwd)\s*[=:]\s*['"][^'"]{4,}['"]""",
        Severity.CRITICAL, Category.SECRET,
        "Hardcoded password detected. Credentials should never be stored in source code.",
        "Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).",
        "CWE-798", None, "high"
    ),
    (
        "SEC002", "Hardcoded API key",
        r"""(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['"][^'"]{8,}['"]""",
        Severity.CRITICAL, Category.SECRET,
        "Hardcoded API key or token detected.",
        "Use environment variables or a secrets manager.",
        "CWE-798", None, "high"
    ),
    (
        "SEC003", "Hardcoded secret/token",
        r"""(?:secret|token|auth[_-]?token|access[_-]?token|bearer)\s*[=:]\s*['"][^'"]{8,}['"]""",
        Severity.CRITICAL, Category.SECRET,
        "Hardcoded secret or authentication token detected.",
        "Rotate this secret immediately and use a secrets manager.",
        "CWE-798", None, "high"
    ),
    (
        "SEC004", "AWS access key",
        r"""(?:AKIA|ASIA)[A-Z0-9]{16}""",
        Severity.CRITICAL, Category.SECRET,
        "AWS access key ID detected in source code.",
        "Remove immediately, rotate the key, and use IAM roles or environment variables.",
        "CWE-798", None, "high"
    ),
    (
        "SEC005", "Private key material",
        r"""-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----""",
        Severity.CRITICAL, Category.SECRET,
        "Private key embedded in source code.",
        "Remove the private key and store it in a secure key management system.",
        "CWE-321", None, "high"
    ),
    (
        "SEC006", "Generic high-entropy secret",
        r"""(?:SECRET|PRIVATE|CREDENTIAL)[_A-Z]*\s*[=:]\s*['"][A-Za-z0-9+/=]{20,}['"]""",
        Severity.HIGH, Category.SECRET,
        "High-entropy string assigned to a secret-looking variable.",
        "Verify this isn't a real credential. Use environment variables for secrets.",
        "CWE-798", None, "medium"
    ),
]

SERVICE_TOKENS = [
    # ── Additional Secret Patterns ──
    (
        "SEC007", "GitHub personal access token",
        r"""ghp_[A-Za-z0-9_]{36}""",
        Severity.CRITICAL, Category.SECRET,
        "GitHub personal access token detected in source code.",
        "Revoke this token at github.com/settings/tokens and use environment variables.",
        "CWE-798", None, "high"
    ),
    (
        "SEC008", "Slack webhook URL",
        r"""https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+""",
        Severity.HIGH, Category.SECRET,
        "Slack webhook URL detected in source code.",
        "Store webhook URLs in environment variables or a secrets manager.",
        "CWE-798", None, "high"
    ),
    (
        "SEC009", "Google API key",
        r"""AIza[0-9A-Za-z\-_]{35}""",
        Severity.HIGH, Category.SECRET,
        "Google API key detected in source code.",
        "Restrict the API key in Google Cloud Console and load from environment variables.",
        "CWE-798", None, "high"
    ),
    (
        "SEC010", "Stripe secret key",
        r"""(?:sk_live|rk_live)_[0-9a-zA-Z]{24,}""",
        Severity.CRITICAL, Category.SECRET,
        "Stripe live secret key detected. This grants full access to payment processing.",
        "Revoke this key in the Stripe dashboard immediately and use environment variables.",
        "CWE-798", None, "high"
    ),
    (
        "SEC011", "Database connection string with credentials",
        r"""(?:mysql|postgres(?:ql)?|mongodb(?:\+srv)?|redis|amqp)://\w+:[^@\s'"]{3,}@""",
        Severity.HIGH, Category.SECRET,
        "Database connection string with embedded credentials found in source code.",
        "Use environment variables for connection strings: os.environ['DATABASE_URL'].",
        "CWE-798", None, "high"
    ),
    (
        "SEC012", "Hardcoded Bearer/Authorization token",
        r"""['"](Bearer\s+[A-Za-z0-9\-_.]{20,})['"]""",
        Severity.HIGH, Category.SECRET,
        "Hardcoded Bearer token in source code.",
        "Load authentication tokens from environment variables or a secrets manager.",
        "CWE-798", None, "medium"
    ),
]

TOKEN_VERIFICATION = [
    # ── JWT / Authentication ──
    (
        "AUTH001", "JWT verification disabled",
        r"""(?:algorithms?\s*[=:]\s*\[?\s*['"]none['"]|jwt\.decode\s*\(.*(?:verify|options).*(?:False|false))""",
        Severity.CRITICAL, Category.SECURITY,
        "JWT verification disabled or 'none' algorithm accepted. Allows forged tokens.",
        "Always verify JWT signatures. Explicitly specify allowed algorithms: algorithms=['HS256'].",
        "CWE-347", None, "high"
    ),
    (
        "AUTH002", "Hardcoded JWT secret",
        r"""jwt\.(?:encode|sign)\s*\(.*['"][^'"]{8,}['"]""",
        Severity.HIGH, Category.SECRET,
        "JWT signed with a hardcoded secret key.",
        "Load the JWT secret from environment variables or a secrets manager.",
        "CWE-798", None, "medium"
    ),
]

LEAKED_VALUES = [
    # ── Environment / Logging ──
    (
        "ENV001", "Environment variable leaked in logs",
        r"""(?:console\.log|print|logger?\.(?:info|debug|warn|error)|logging\.)\s*\(.*(?:os\.environ|process\.env)""",
        Severity.MEDIUM, Category.SECRET,
        "Environment variable value written to logs may leak secrets.",
        "Never log raw environment variable values. Mask sensitive values before logging.",
        "CWE-532", None, "low"
    ),
]
