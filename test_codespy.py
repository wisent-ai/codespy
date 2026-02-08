#!/usr/bin/env python3
"""Tests for codespy - code security scanner."""

import json
import os
import sys
import tempfile
import shutil

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from codespy import (
    run_scan, scan_file, collect_files, detect_language_from_path,
    compute_score, score_to_grade, parse_severity,
    format_json, format_terminal, format_markdown, format_sarif,
    Severity, Category, Finding, ScanResult, RULES,
)


passed = 0
failed = 0


def assert_true(condition, msg=""):
    global passed, failed
    if condition:
        passed += 1
    else:
        failed += 1
        print(f"  FAIL: {msg}")


def assert_eq(a, b, msg=""):
    assert_true(a == b, f"{msg} — expected {b!r}, got {a!r}")


def assert_in(item, container, msg=""):
    assert_true(item in container, f"{msg} — {item!r} not in result")


def assert_gte(a, b, msg=""):
    assert_true(a >= b, f"{msg} — {a} < {b}")


def assert_gt(a, b, msg=""):
    assert_true(a > b, f"{msg} — {a} <= {b}")


# ─── Helpers ────────────────────────────────────────────────────────────────

def create_temp_project(files: dict) -> str:
    """Create a temporary directory with files. Returns path."""
    tmpdir = tempfile.mkdtemp(prefix="codespy_test_")
    for name, content in files.items():
        path = os.path.join(tmpdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    return tmpdir


def cleanup(path):
    shutil.rmtree(path, ignore_errors=True)


# ─── Test Language Detection ────────────────────────────────────────────────

def test_language_detection():
    print("Testing language detection...")
    assert_eq(detect_language_from_path("main.py"), "python", "Python detection")
    assert_eq(detect_language_from_path("app.js"), "javascript", "JS detection")
    assert_eq(detect_language_from_path("index.ts"), "typescript", "TS detection")
    assert_eq(detect_language_from_path("main.go"), "go", "Go detection")
    assert_eq(detect_language_from_path("lib.rs"), "rust", "Rust detection")
    assert_eq(detect_language_from_path("App.java"), "java", "Java detection")
    assert_eq(detect_language_from_path("Dockerfile"), "dockerfile", "Dockerfile detection")
    assert_eq(detect_language_from_path("Dockerfile.prod"), "dockerfile", "Dockerfile.prod detection")
    assert_eq(detect_language_from_path("script.sh"), "shell", "Shell detection")
    assert_eq(detect_language_from_path("config.tf"), "terraform", "Terraform detection")
    assert_eq(detect_language_from_path("README.md"), None, "Non-code file returns None")
    assert_eq(detect_language_from_path("image.png"), None, "Image returns None")


# ─── Test File Collection ───────────────────────────────────────────────────

def test_file_collection():
    print("Testing file collection...")
    tmpdir = create_temp_project({
        "main.py": "print('hello')",
        "app.js": "console.log('hello')",
        "README.md": "# Hello",
        "src/lib.py": "def foo(): pass",
        "node_modules/pkg/index.js": "module.exports = {}",
        ".git/config": "[core]",
    })

    try:
        files = collect_files(tmpdir)
        paths = [os.path.basename(f[0]) for f in files]

        assert_in("main.py", paths, "Finds Python files")
        assert_in("app.js", paths, "Finds JS files")
        assert_in("lib.py", paths, "Finds nested Python files")
        assert_true("README.md" not in [os.path.basename(f[0]) for f in files],
                    "Skips non-code files")
        assert_true("index.js" not in paths, "Skips node_modules")
        assert_true("config" not in paths, "Skips .git")
    finally:
        cleanup(tmpdir)


# ─── Test Secret Detection ──────────────────────────────────────────────────

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


# ─── Test Injection Detection ───────────────────────────────────────────────

def test_sql_injection():
    print("Testing SQL injection detection...")
    tmpdir = create_temp_project({
        "db.py": """
def get_user(name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("INJ001", rule_ids, "Detects SQL injection")
    finally:
        cleanup(tmpdir)


def test_shell_injection():
    print("Testing shell injection detection...")
    tmpdir = create_temp_project({
        "run.py": """
import subprocess
def execute(cmd):
    subprocess.call(cmd, shell=True)
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("INJ002", rule_ids, "Detects shell injection")
    finally:
        cleanup(tmpdir)


def test_eval_detection():
    print("Testing eval detection...")
    tmpdir = create_temp_project({
        "code.py": """
result = eval(user_input)
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("INJ004", rule_ids, "Detects eval usage")
    finally:
        cleanup(tmpdir)


def test_unsafe_yaml():
    print("Testing unsafe YAML detection...")
    tmpdir = create_temp_project({
        "load.py": """
import yaml
data = yaml.load(content)
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("INJ005", rule_ids, "Detects unsafe YAML")
    finally:
        cleanup(tmpdir)


def test_xss_detection():
    print("Testing XSS / innerHTML detection...")
    tmpdir = create_temp_project({
        "app.js": """
document.getElementById('content').innerHTML = userInput;
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("INJ006", rule_ids, "Detects innerHTML XSS")
    finally:
        cleanup(tmpdir)


# ─── Test Configuration Issues ──────────────────────────────────────────────

def test_debug_mode():
    print("Testing debug mode detection...")
    tmpdir = create_temp_project({
        "settings.py": """
DEBUG = True
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("CFG001", rule_ids, "Detects debug mode")
    finally:
        cleanup(tmpdir)


def test_cors_wildcard():
    print("Testing CORS wildcard detection...")
    tmpdir = create_temp_project({
        "server.py": """
cors_allow_origins = "*"
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("CFG002", rule_ids, "Detects CORS wildcard")
    finally:
        cleanup(tmpdir)


def test_ssl_disabled():
    print("Testing disabled SSL detection...")
    tmpdir = create_temp_project({
        "client.py": """
requests.get(url, verify=False)
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("CFG004", rule_ids, "Detects disabled SSL")
    finally:
        cleanup(tmpdir)


# ─── Test Code Quality ──────────────────────────────────────────────────────

def test_todo_detection():
    print("Testing TODO/FIXME detection...")
    tmpdir = create_temp_project({
        "main.py": """
# TODO: fix this later
# FIXME: urgent bug
def broken(): pass
""",
    })

    try:
        result = run_scan(tmpdir)
        todo_findings = [f for f in result.findings if f.rule_id == "QUA001"]
        assert_gte(len(todo_findings), 2, "Detects TODO and FIXME")
    finally:
        cleanup(tmpdir)


def test_mutable_default():
    print("Testing mutable default argument detection...")
    tmpdir = create_temp_project({
        "func.py": """
def process(items=[]):
    items.append(1)
    return items
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("QUA003", rule_ids, "Detects mutable default argument")
    finally:
        cleanup(tmpdir)


def test_console_log():
    print("Testing console.log detection in JS...")
    tmpdir = create_temp_project({
        "debug.js": """
function handler(req) {
    console.log("debug:", req.body);
    return process(req);
}
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("QUA005", rule_ids, "Detects console.log")
    finally:
        cleanup(tmpdir)


# ─── Test Clean Code ────────────────────────────────────────────────────────

def test_clean_code():
    print("Testing clean code gets high score...")
    tmpdir = create_temp_project({
        "clean.py": """
def add(a: int, b: int) -> int:
    return a + b

def greet(name: str) -> str:
    return f"Hello, {name}!"
""",
    })

    try:
        result = run_scan(tmpdir)
        score = compute_score(result)
        assert_gte(score, 90, f"Clean code scores high: {score}")
        assert_eq(len(result.findings), 0, "No findings for clean code")
    finally:
        cleanup(tmpdir)


# ─── Test Scoring ───────────────────────────────────────────────────────────

def test_scoring():
    print("Testing scoring system...")
    assert_eq(score_to_grade(100), "A+", "Perfect score = A+")
    assert_eq(score_to_grade(95), "A+", "95 = A+")
    assert_eq(score_to_grade(90), "A", "90 = A")
    assert_eq(score_to_grade(80), "B+", "80 = B+")
    assert_eq(score_to_grade(70), "B", "70 = B")
    assert_eq(score_to_grade(60), "C", "60 = C")
    assert_eq(score_to_grade(50), "D", "50 = D")
    assert_eq(score_to_grade(30), "F", "30 = F")


def test_severity_parsing():
    print("Testing severity parsing...")
    assert_eq(parse_severity("info"), Severity.INFO, "Parse info")
    assert_eq(parse_severity("critical"), Severity.CRITICAL, "Parse critical")
    assert_eq(parse_severity("HIGH"), Severity.HIGH, "Parse HIGH (case insensitive)")

    try:
        parse_severity("invalid")
        assert_true(False, "Should raise ValueError for invalid severity")
    except ValueError:
        assert_true(True, "Raises ValueError for invalid severity")


# ─── Test Output Formats ───────────────────────────────────────────────────

def test_json_output():
    print("Testing JSON output...")
    tmpdir = create_temp_project({
        "main.py": "password = 'test1234'\n",
    })

    try:
        result = run_scan(tmpdir)
        output = format_json(result)
        parsed = json.loads(output)
        assert_in("findings", parsed, "JSON has findings key")
        assert_in("severity_counts", parsed, "JSON has severity_counts")
        assert_in("language_stats", parsed, "JSON has language_stats")
        assert_gt(parsed["total_findings"], 0, "JSON reports findings")
    finally:
        cleanup(tmpdir)


def test_sarif_output():
    print("Testing SARIF output...")
    tmpdir = create_temp_project({
        "vuln.py": "password = 'hunter2abc'\n",
    })

    try:
        result = run_scan(tmpdir)
        output = format_sarif(result)
        parsed = json.loads(output)
        assert_eq(parsed["version"], "2.1.0", "SARIF version 2.1.0")
        assert_in("runs", parsed, "SARIF has runs")
        assert_eq(parsed["runs"][0]["tool"]["driver"]["name"], "codespy", "Tool name is codespy")
        assert_gt(len(parsed["runs"][0]["results"]), 0, "SARIF has results")
    finally:
        cleanup(tmpdir)


def test_markdown_output():
    print("Testing markdown output...")
    tmpdir = create_temp_project({
        "app.py": "password = 'insecure!'\n",
    })

    try:
        result = run_scan(tmpdir)
        output = format_markdown(result, show_fix=True)
        assert_in("# codespy Security Report", output, "Markdown has title")
        assert_in("Security Score", output, "Markdown has score")
        assert_in("Findings", output, "Markdown has findings section")
        assert_in("Fix:", output, "Markdown shows fixes when requested")
    finally:
        cleanup(tmpdir)


def test_terminal_output():
    print("Testing terminal output...")
    tmpdir = create_temp_project({
        "app.py": "password = 'mysecret1'\n",
    })

    try:
        result = run_scan(tmpdir)
        output = format_terminal(result, show_fix=True, use_color=False)
        assert_in("codespy", output, "Terminal output has tool name")
        assert_in("Security Score", output, "Terminal output has score")
    finally:
        cleanup(tmpdir)


# ─── Test Severity Filtering ───────────────────────────────────────────────

def test_severity_filter():
    print("Testing severity filtering...")
    tmpdir = create_temp_project({
        "mixed.py": """
# TODO: fix this
password = "secretpass1"
DEBUG = True
""",
    })

    try:
        # Scan all
        all_result = run_scan(tmpdir, min_severity=Severity.INFO)
        # Scan high+ only
        high_result = run_scan(tmpdir, min_severity=Severity.HIGH)

        assert_gte(all_result.finding_count, high_result.finding_count,
                   "All findings >= high-only findings")
        assert_gt(all_result.finding_count, 0, "Info scan finds issues")

        # Verify high results only have high/critical
        for f in high_result.findings:
            assert_true(f.severity in (Severity.HIGH, Severity.CRITICAL),
                        f"High filter: {f.severity.value} should be high or critical")
    finally:
        cleanup(tmpdir)


# ─── Test Dockerfile ────────────────────────────────────────────────────────

def test_dockerfile_latest_tag():
    print("Testing Dockerfile latest tag detection...")
    tmpdir = create_temp_project({
        "Dockerfile": """FROM python:latest
RUN pip install flask
CMD ["python", "app.py"]
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("DOC002", rule_ids, "Detects :latest tag in Dockerfile")
    finally:
        cleanup(tmpdir)


# ─── Test Terraform ─────────────────────────────────────────────────────────

def test_terraform_public_bucket():
    print("Testing Terraform public bucket detection...")
    tmpdir = create_temp_project({
        "main.tf": """
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("IAC001", rule_ids, "Detects public S3 bucket")
    finally:
        cleanup(tmpdir)


# ─── Test Go SQL Injection ──────────────────────────────────────────────────

def test_go_sql_injection():
    print("Testing Go SQL injection detection...")
    tmpdir = create_temp_project({
        "main.go": """
package main

func getUser(db *sql.DB, name string) {
    db.Query(fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name))
}
""",
    })

    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("INJ009", rule_ids, "Detects Go SQL injection")
    finally:
        cleanup(tmpdir)


# ─── Test Single File Scan ──────────────────────────────────────────────────

def test_single_file_scan():
    print("Testing single file scan...")
    tmpdir = create_temp_project({
        "target.py": "password = 'leaked123'\n",
        "other.py": "api_key = 'sk-abcdefghijk'\n",
    })

    try:
        # Scan just one file
        result = run_scan(os.path.join(tmpdir, "target.py"))
        assert_eq(result.files_scanned, 1, "Only scans one file")

        # Should only find issues in target.py, not other.py
        for f in result.findings:
            assert_true("other.py" not in f.file_path, "Doesn't scan other files")
    finally:
        cleanup(tmpdir)


# ─── Test Empty Project ────────────────────────────────────────────────────

def test_empty_project():
    print("Testing empty project scan...")
    tmpdir = tempfile.mkdtemp(prefix="codespy_empty_")
    try:
        result = run_scan(tmpdir)
        assert_eq(result.files_scanned, 0, "No files scanned")
        assert_eq(result.finding_count, 0, "No findings")
        assert_eq(compute_score(result), 100, "Perfect score for empty project")
    finally:
        cleanup(tmpdir)


# ─── Test Data Models ───────────────────────────────────────────────────────

def test_finding_to_dict():
    print("Testing Finding serialization...")
    finding = Finding(
        rule_id="SEC001",
        title="Test finding",
        description="A test",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        file_path="test.py",
        line_number=10,
        line_content="  password = 'test'",
        suggestion="Don't do this",
        cwe_id="CWE-798",
    )
    d = finding.to_dict()
    assert_eq(d["rule_id"], "SEC001", "Dict has rule_id")
    assert_eq(d["severity"], "high", "Severity is string")
    assert_eq(d["cwe_id"], "CWE-798", "Has CWE ID")
    assert_eq(d["line_content"], "password = 'test'", "Line content is stripped")


def test_scan_result_properties():
    print("Testing ScanResult properties...")
    result = ScanResult(path="/test")
    result.findings = [
        Finding("R1", "T1", "D1", Severity.HIGH, Category.SECURITY, "f.py", 1, "", "", ""),
        Finding("R2", "T2", "D2", Severity.HIGH, Category.INJECTION, "f.py", 2, "", "", ""),
        Finding("R3", "T3", "D3", Severity.LOW, Category.QUALITY, "f.py", 3, "", "", ""),
    ]
    assert_eq(result.finding_count, 3, "Finding count")
    assert_eq(result.severity_counts.get("high"), 2, "High severity count")
    assert_eq(result.severity_counts.get("low"), 1, "Low severity count")
    assert_eq(result.category_counts.get("security"), 1, "Security category count")


# ─── Test New Secret Patterns ──────────────────────────────────────────────

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


# ─── Test SSRF Detection ──────────────────────────────────────────────────

def test_ssrf_python():
    print("Testing Python SSRF detection...")
    tmpdir = create_temp_project({
        "api.py": """
import requests

def fetch_url(request):
    url = request.args.get('url')
    response = requests.get(f"https://{url}/data")
    return response.json()
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("SSRF001", rule_ids, "Detects Python SSRF via requests")
    finally:
        cleanup(tmpdir)


# ─── Test Open Redirect ──────────────────────────────────────────────────

def test_open_redirect():
    print("Testing open redirect detection...")
    tmpdir = create_temp_project({
        "views.py": """
from django.shortcuts import redirect

def login_redirect(request):
    next_url = request.GET.get('next')
    return redirect(request.GET.get('next'))
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("REDIR001", rule_ids, "Detects open redirect in Python")
    finally:
        cleanup(tmpdir)


# ─── Test React XSS ──────────────────────────────────────────────────────

def test_react_xss():
    print("Testing React dangerouslySetInnerHTML detection...")
    tmpdir = create_temp_project({
        "component.tsx": """
function UserProfile({ html }) {
    return <div dangerouslySetInnerHTML={{ __html: html }} />;
}
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("REACT001", rule_ids, "Detects dangerouslySetInnerHTML")
    finally:
        cleanup(tmpdir)


def test_document_write():
    print("Testing document.write detection...")
    tmpdir = create_temp_project({
        "legacy.js": 'document.write("<script>alert(1)</script>")\n',
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("JS001", rule_ids, "Detects document.write()")
    finally:
        cleanup(tmpdir)


# ─── Test Django/Flask Specific ──────────────────────────────────────────

def test_django_mark_safe():
    print("Testing Django mark_safe detection...")
    tmpdir = create_temp_project({
        "views.py": """
from django.utils.safestring import mark_safe

def render(user_input):
    return mark_safe(f"<p>{user_input}</p>")
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("DJANGO001", rule_ids, "Detects mark_safe with f-string")
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


# ─── Test Kubernetes Security ──────────────────────────────────────────────

def test_k8s_privileged():
    print("Testing Kubernetes privileged container detection...")
    tmpdir = create_temp_project({
        "deployment.yml": """
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: app
        securityContext:
          privileged: true
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("K8S001", rule_ids, "Detects privileged Kubernetes container")
    finally:
        cleanup(tmpdir)


def test_k8s_host_network():
    print("Testing Kubernetes hostNetwork detection...")
    tmpdir = create_temp_project({
        "pod.yaml": """
apiVersion: v1
kind: Pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: myapp:1.0
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("K8S003", rule_ids, "Detects Kubernetes hostNetwork")
    finally:
        cleanup(tmpdir)


# ─── Test Dockerfile New Rules ──────────────────────────────────────────────

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


# ─── Test Crypto Issues ──────────────────────────────────────────────────

def test_weak_cipher():
    print("Testing weak cipher detection...")
    tmpdir = create_temp_project({
        "crypto.py": """
from Crypto.Cipher import DES
cipher = DES.new(key, DES.MODE_ECB)
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("CRYPTO001", rule_ids, "Detects weak cipher (DES)")
    finally:
        cleanup(tmpdir)


# ─── Test Node.js TLS ──────────────────────────────────────────────────

def test_node_tls_disabled():
    print("Testing Node.js TLS verification disabled...")
    tmpdir = create_temp_project({
        "server.js": """
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const https = require('https');
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("JS003", rule_ids, "Detects disabled TLS verification in Node.js")
    finally:
        cleanup(tmpdir)


# ─── Test SSTI ──────────────────────────────────────────────────────────

def test_ssti():
    print("Testing server-side template injection detection...")
    tmpdir = create_temp_project({
        "app.py": """
from flask import render_template_string, request

@app.route('/greet')
def greet():
    name = request.args.get('name')
    return render_template_string('<h1>Hello {{ name }}</h1>', name=name)
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("SSTI001", rule_ids, "Detects render_template_string (SSTI)")
    finally:
        cleanup(tmpdir)


# ─── Test Terraform Publicly Accessible RDS ──────────────────────────────

def test_terraform_public_rds():
    print("Testing Terraform public RDS detection...")
    tmpdir = create_temp_project({
        "rds.tf": """
resource "aws_db_instance" "default" {
  engine         = "mysql"
  instance_class = "db.t3.micro"
  publicly_accessible = true
}
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("IAC003", rule_ids, "Detects publicly accessible RDS instance")
    finally:
        cleanup(tmpdir)


# ─── Test Math.random ──────────────────────────────────────────────────

def test_js_math_random():
    print("Testing JavaScript Math.random() detection...")
    tmpdir = create_temp_project({
        "auth.js": """
function generateToken() {
    return Math.random().toString(36).substring(2);
}
""",
    })
    try:
        result = run_scan(tmpdir)
        rule_ids = [f.rule_id for f in result.findings]
        assert_in("JS004", rule_ids, "Detects Math.random() usage")
    finally:
        cleanup(tmpdir)


# ─── Test Rule Count ──────────────────────────────────────────────────

def test_rule_count():
    print("Testing rule count...")
    assert_gte(len(RULES), 65, "At least 65 rules defined")


# ─── Run All Tests ──────────────────────────────────────────────────────────

def run_all():
    global passed, failed

    tests = [
        test_language_detection,
        test_file_collection,
        test_secrets,
        test_aws_key_detection,
        test_private_key_detection,
        test_sql_injection,
        test_shell_injection,
        test_eval_detection,
        test_unsafe_yaml,
        test_xss_detection,
        test_debug_mode,
        test_cors_wildcard,
        test_ssl_disabled,
        test_todo_detection,
        test_mutable_default,
        test_console_log,
        test_clean_code,
        test_scoring,
        test_severity_parsing,
        test_json_output,
        test_sarif_output,
        test_markdown_output,
        test_terminal_output,
        test_severity_filter,
        test_dockerfile_latest_tag,
        test_terraform_public_bucket,
        test_go_sql_injection,
        test_single_file_scan,
        test_empty_project,
        test_finding_to_dict,
        test_scan_result_properties,
        # New rule tests
        test_github_token,
        test_stripe_key,
        test_db_connection_string,
        test_ssrf_python,
        test_open_redirect,
        test_react_xss,
        test_document_write,
        test_django_mark_safe,
        test_flask_secret_key,
        test_k8s_privileged,
        test_k8s_host_network,
        test_dockerfile_secrets_in_args,
        test_weak_cipher,
        test_node_tls_disabled,
        test_ssti,
        test_terraform_public_rds,
        test_js_math_random,
        test_rule_count,
    ]

    print(f"\n{'=' * 60}")
    print(f"codespy test suite — {len(tests)} test functions")
    print(f"{'=' * 60}\n")

    for test in tests:
        try:
            test()
        except Exception as e:
            failed += 1
            print(f"  ERROR in {test.__name__}: {e}")

    print(f"\n{'=' * 60}")
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    print(f"{'=' * 60}\n")

    return failed == 0


if __name__ == "__main__":
    success = run_all()
    sys.exit(0 if success else 1)
