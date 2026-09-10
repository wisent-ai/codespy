"""Injection rules across Python, JavaScript, Go, and web frameworks."""

from codespy import run_scan
from support import assert_in, cleanup, create_temp_project


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


TESTS = (
    test_sql_injection,
    test_shell_injection,
    test_eval_detection,
    test_unsafe_yaml,
    test_xss_detection,
    test_go_sql_injection,
    test_ssrf_python,
    test_open_redirect,
    test_react_xss,
    test_document_write,
    test_django_mark_safe,
    test_ssti,
)
