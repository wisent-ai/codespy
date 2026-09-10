"""Insecure settings across application, crypto, container, cluster, and cloud code."""

from ..models import Category, Severity

APPLICATION_SETTINGS = [
    # ── Security Misconfigurations ──
    (
        "CFG001", "Debug mode enabled",
        r"""(?:DEBUG|debug)\s*[=:]\s*(?:True|true|1|'true'|"true")""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "Debug mode appears to be enabled. This can expose sensitive information.",
        "Ensure debug mode is disabled in production.",
        "CWE-215", None, "medium"
    ),
    (
        "CFG002", "CORS wildcard",
        r"""(?:Access-Control-Allow-Origin|cors(?:_allow)?_origin[s]?)\s*[=:]\s*['"]\*['"]""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "CORS configured to allow all origins. This may expose APIs to unauthorized access.",
        "Restrict CORS to specific trusted domains.",
        "CWE-942", None, "medium"
    ),
    (
        "CFG003", "Insecure HTTP URL",
        r"""https?://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1|example\.com|example\.org)[a-zA-Z0-9.-]+\.[a-z]{2,}""",
        Severity.INFO, Category.CONFIGURATION,
        "HTTP URLs detected. Consider using HTTPS.",
        "Use HTTPS for all external communications.",
        "", None, "low"
    ),
    (
        "CFG004", "Disabled SSL verification",
        r"""verify\s*=\s*False""",
        Severity.HIGH, Category.SECURITY,
        "SSL certificate verification is disabled, enabling man-in-the-middle attacks.",
        "Enable SSL verification (verify=True) and use proper certificate management.",
        "CWE-295", {"python"}, "high"
    ),
    (
        "CFG005", "Insecure random for security",
        r"""(?:random\.(?:random|randint|choice|randrange))\s*\(""",
        Severity.MEDIUM, Category.SECURITY,
        "Standard random module is not cryptographically secure.",
        "Use secrets module for security-sensitive randomness: secrets.token_hex(), secrets.randbelow().",
        "CWE-338", {"python"}, "low"
    ),
    (
        "CFG006", "Weak hash algorithm",
        r"""(?:hashlib\.(?:md5|sha1)|MD5|SHA1)\s*\(""",
        Severity.MEDIUM, Category.SECURITY,
        "Weak hash algorithm (MD5/SHA1) detected. These are vulnerable to collisions.",
        "Use SHA-256 or stronger: hashlib.sha256().",
        "CWE-328", None, "medium"
    ),
    (
        "CFG007", "Permissive file permissions",
        r"""(?:chmod|os\.chmod)\s*\(.*0o?777""",
        Severity.HIGH, Category.CONFIGURATION,
        "File permissions set to 777 (world-readable/writable/executable).",
        "Use more restrictive permissions (e.g., 0o644 for files, 0o755 for directories).",
        "CWE-732", None, "high"
    ),
]

SUPPLY_CHAIN = [
    # ── Supply Chain ──
    (
        "SUP001", "Unpinned dependency",
        r"""(?:pip install|gem install|npm install)\s+[a-zA-Z][\w-]*\s*$""",
        Severity.LOW, Category.SUPPLY_CHAIN,
        "Installing package without version pinning.",
        "Pin dependencies to specific versions for reproducible builds.",
        "CWE-1104", None, "low"
    ),
]

CONTAINER_IMAGES = [
    # ── Dockerfile Security ──
    (
        "DOC001", "Running as root in Docker",
        r"""^(?!.*USER\s).*(?:CMD|ENTRYPOINT)""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "Container may be running as root (no USER directive before CMD/ENTRYPOINT).",
        "Add a USER directive to run as non-root: USER nonroot",
        "CWE-250", {"dockerfile"}, "low"
    ),
    (
        "DOC002", "Latest tag in Docker FROM",
        r"""FROM\s+\w+(?::\s*latest|\s*$)""",
        Severity.LOW, Category.SUPPLY_CHAIN,
        "Using 'latest' or untagged base image makes builds non-reproducible.",
        "Pin to a specific version: FROM python:3.11-slim",
        "", {"dockerfile"}, "medium"
    ),
]

INFRASTRUCTURE = [
    # ── Terraform / IaC ──
    (
        "IAC001", "Public S3 bucket",
        r"""acl\s*=\s*['"]public-read['"]""",
        Severity.HIGH, Category.CONFIGURATION,
        "S3 bucket configured with public read access.",
        "Use 'private' ACL unless public access is explicitly required.",
        "CWE-284", {"terraform"}, "high"
    ),
    (
        "IAC002", "Open security group",
        r"""cidr_blocks\s*=\s*\[['"]0\.0\.0\.0/0['"]\]""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "Security group open to all IPs (0.0.0.0/0).",
        "Restrict to specific IP ranges or use a VPN.",
        "CWE-284", {"terraform"}, "medium"
    ),
]

CRYPTOGRAPHY = [
    # ── Cryptographic Issues ──
    (
        "CRYPTO001", "Weak cipher or ECB mode",
        r"""(?:DES|RC4|RC2|Blowfish|AES\.MODE_ECB|mode\s*=\s*['"]?ECB|createCipheriv\s*\(\s*['"](?:des|rc4|aes-\d+-ecb))""",
        Severity.HIGH, Category.SECURITY,
        "Weak cipher algorithm or insecure ECB block cipher mode detected.",
        "Use AES-256-GCM or AES-256-CBC with proper IV. Never use DES, RC4, or ECB mode.",
        "CWE-327", None, "high"
    ),
    (
        "CRYPTO002", "Hardcoded initialization vector",
        r"""(?:iv|nonce|IV|NONCE)\s*=\s*(?:b['"][^'"]{8,}['"]|bytes\(|b'\\x)""",
        Severity.HIGH, Category.SECURITY,
        "Hardcoded initialization vector (IV) makes encryption predictable.",
        "Generate a random IV for each encryption operation using os.urandom() or crypto.randomBytes().",
        "CWE-329", None, "medium"
    ),
]

JAVASCRIPT_RUNTIME = [
    (
        "JS003", "Node.js TLS verification disabled",
        r"""(?:NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized)\s*[=:]\s*(?:['"]?0['"]?|false)""",
        Severity.HIGH, Category.SECURITY,
        "TLS certificate verification disabled. Enables man-in-the-middle attacks.",
        "Enable TLS verification. Use proper CA certificates for self-signed certs.",
        "CWE-295", {"javascript", "typescript"}, "high"
    ),
    (
        "JS004", "Math.random() for security",
        r"""Math\.random\s*\(\s*\)""",
        Severity.MEDIUM, Category.SECURITY,
        "Math.random() is not cryptographically secure and should not be used for security.",
        "Use crypto.randomUUID(), crypto.getRandomValues(), or crypto.randomBytes().",
        "CWE-338", {"javascript", "typescript"}, "low"
    ),
]

PYTHON_RUNTIME = [
    # ── Python-Specific ──
    (
        "PY001", "Insecure temporary file creation",
        r"""(?:tempfile\.mktemp|os\.tempnam|os\.tmpnam)\s*\(""",
        Severity.MEDIUM, Category.SECURITY,
        "Insecure temporary file creation is vulnerable to race condition attacks.",
        "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead.",
        "CWE-377", {"python"}, "high"
    ),
    (
        "PY002", "Assert used for security validation",
        r"""assert\s+.*(?:is_authenticated|is_staff|is_superuser|has_perm|is_admin)""",
        Severity.HIGH, Category.SECURITY,
        "assert statements are removed when Python runs with -O flag. Never use for security checks.",
        "Use if/raise for security: if not user.is_authenticated: raise PermissionError().",
        "CWE-617", {"python"}, "medium"
    ),
]

KUBERNETES = [
    # ── Kubernetes / Container Security ──
    (
        "K8S001", "Privileged Kubernetes container",
        r"""privileged\s*:\s*true""",
        Severity.CRITICAL, Category.CONFIGURATION,
        "Container running in privileged mode has full host access.",
        "Remove privileged: true. Use specific capabilities if needed.",
        "CWE-250", {"yaml"}, "high"
    ),
    (
        "K8S002", "Container running as root in Kubernetes",
        r"""runAsUser\s*:\s*0\b""",
        Severity.HIGH, Category.CONFIGURATION,
        "Kubernetes pod configured to run as root user.",
        "Set runAsNonRoot: true and specify a non-zero runAsUser in securityContext.",
        "CWE-250", {"yaml"}, "high"
    ),
    (
        "K8S003", "Kubernetes host namespace sharing",
        r"""(?:hostNetwork|hostPID|hostIPC)\s*:\s*true""",
        Severity.HIGH, Category.CONFIGURATION,
        "Pod shares the host's network/PID/IPC namespace, breaking container isolation.",
        "Remove hostNetwork/hostPID/hostIPC unless absolutely required.",
        "CWE-250", {"yaml"}, "high"
    ),
]

CONTAINER_BUILDS = [
    # ── Additional Dockerfile Rules ──
    (
        "DOC003", "Docker ADD instead of COPY",
        r"""\bADD\s+(?!https?://)""",
        Severity.LOW, Category.CONFIGURATION,
        "ADD instruction used instead of COPY. ADD can auto-extract archives and fetch URLs unexpectedly.",
        "Use COPY unless you specifically need ADD's tar extraction or URL fetching features.",
        "", {"dockerfile"}, "medium"
    ),
    (
        "DOC004", "Secret in Docker ARG/ENV",
        r"""(?:ARG|ENV)\s+(?:\w*(?:PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY|CREDENTIAL)\w*)\b""",
        Severity.HIGH, Category.SECRET,
        "Secret passed via ARG or ENV in Dockerfile. ARG values are visible in docker history.",
        "Use Docker BuildKit secrets (--mount=type=secret) or runtime environment variables.",
        "CWE-798", {"dockerfile"}, "medium"
    ),
    (
        "DOC005", "Sensitive port exposed in Dockerfile",
        r"""EXPOSE\s+(?:22|3389|5432|3306|6379|27017|11211)\b""",
        Severity.MEDIUM, Category.CONFIGURATION,
        "Sensitive service port (SSH/DB/cache) exposed in Dockerfile.",
        "Avoid exposing database or management ports. Use Docker networks for inter-service communication.",
        "CWE-284", {"dockerfile"}, "medium"
    ),
]

MANAGED_DATABASES = [
    # ── Additional IaC Rules ──
    (
        "IAC003", "Publicly accessible RDS instance",
        r"""publicly_accessible\s*=\s*true""",
        Severity.HIGH, Category.CONFIGURATION,
        "RDS database instance is publicly accessible from the internet.",
        "Set publicly_accessible = false and use private subnets with VPN/bastion access.",
        "CWE-284", {"terraform"}, "high"
    ),
]

REQUEST_HANDLING = [
    # ── Mass Assignment ──
    (
        "API001", "Potential mass assignment",
        r"""(?:\.create|\.update|\.findOneAndUpdate|\.updateOne)\s*\(\s*(?:req\.body|request\.(?:data|json))""",
        Severity.MEDIUM, Category.SECURITY,
        "Directly passing request body to database operations may allow mass assignment.",
        "Explicitly pick allowed fields. Use serializer validation or an allowlist.",
        "CWE-915", {"javascript", "typescript", "python"}, "medium"
    ),
]
