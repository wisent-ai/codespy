"""Credential rules, each driven through a real scan of a disposable project."""

from codespy import Severity, run_scan
from support import assert_eq, assert_in, cleanup, create_temp_project


def test_secrets():
    print("Testing secret detection...")
    tmpdir = create_temp_project({
        "config.py": """
password = "supersecret123"
api_key = "sk-1234567890abcdef"
db_url = "postgres://localhost/mydb"
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("SEC001", rule_ids, "Detects hardcoded password")
        assert_in("SEC002", rule_ids, "Detects API key")

        # Check severity
        for f in result.findings:
            if f.rule_id in ("SEC001", "SEC002"):
                assert_eq(f.severity, Severity.CRITICAL, f"Secret {f.rule_id} is CRITICAL")
    finally:
        cleanup(tmpdir)


def test_aws_key_detection():
    print("Testing AWS key detection...")
    tmpdir = create_temp_project({
        "deploy.py": """
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("SEC004", rule_ids, "Detects AWS access key")
    finally:
        cleanup(tmpdir)


def test_private_key_detection():
    print("Testing private key detection...")
    tmpdir = create_temp_project({
        "key.py": """
key = \"\"\"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----\"\"\"
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("SEC005", rule_ids, "Detects private key")
    finally:
        cleanup(tmpdir)


def test_github_token():
    print("Testing GitHub token detection...")
    tmpdir = create_temp_project({
        "config.py": 'token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"\n',
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("SEC007", rule_ids, "Detects GitHub personal access token")
    finally:
        cleanup(tmpdir)


def test_stripe_key():
    print("Testing Stripe key detection...")
    # Use a clearly fake key pattern that matches the rule but won't trigger push protection
    stripe_key = "sk_" + "live" + "_" + "a1b2c3d4e5f6g7h8i9j0k1l2m3n4"
    tmpdir = create_temp_project({
        "payment.py": f'key = "{stripe_key}"\n',
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("SEC010", rule_ids, "Detects Stripe live secret key")
    finally:
        cleanup(tmpdir)


def test_db_connection_string():
    print("Testing database connection string detection...")
    tmpdir = create_temp_project({
        "settings.py": 'DATABASE_URL = "postgres://admin:s3cretpass@db.example.com:5432/mydb"\n',
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("SEC011", rule_ids, "Detects database connection string with credentials")
    finally:
        cleanup(tmpdir)


def test_flask_secret_key():
    print("Testing Flask SECRET_KEY detection...")
    tmpdir = create_temp_project({
        "app.py": """
from flask import Flask
app = Flask(__name__)
app.secret_key = "my-super-secret-key-12345"
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("FLASK001", rule_ids, "Detects hardcoded Flask SECRET_KEY")
    finally:
        cleanup(tmpdir)


def test_dockerfile_secrets_in_args():
    print("Testing Dockerfile secret in ARG detection...")
    tmpdir = create_temp_project({
        "Dockerfile": """
FROM python:3.12-slim
ARG DATABASE_PASSWORD
ARG API_SECRET_KEY
ENV APP_TOKEN mytoken123
RUN pip install flask
CMD ["python", "app.py"]
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("DOC004", rule_ids, "Detects secrets in Dockerfile ARG/ENV")
    finally:
        cleanup(tmpdir)


TESTS = (
    test_secrets,
    test_aws_key_detection,
    test_private_key_detection,
    test_github_token,
    test_stripe_key,
    test_db_connection_string,
    test_flask_secret_key,
    test_dockerfile_secrets_in_args,
)
