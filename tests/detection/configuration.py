"""Insecure settings in application, container, cluster, and cloud sources."""

from codespy import run_scan
from support import assert_in, cleanup, create_temp_project


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


TESTS = (
    test_debug_mode,
    test_cors_wildcard,
    test_ssl_disabled,
    test_dockerfile_latest_tag,
    test_terraform_public_bucket,
    test_k8s_privileged,
    test_k8s_host_network,
    test_weak_cipher,
    test_node_tls_disabled,
    test_terraform_public_rds,
    test_js_math_random,
)
