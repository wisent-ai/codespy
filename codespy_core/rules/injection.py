"""Untrusted input reaching code, queries, commands, requests, paths, and markup."""

from ..models import Category, Severity

CODE_EXECUTION = [
    # ── Injection Vulnerabilities ──
    (
        "INJ001", "SQL injection risk",
        r"""(?:execute|cursor\.execute|query)\s*\(\s*(?:f['"]|['"].*%s|['"].*\+\s*\w+|['"].*\.format\()""",
        Severity.HIGH, Category.INJECTION,
        "Potential SQL injection via string formatting in query.",
        "Use parameterized queries: cursor.execute('SELECT * FROM t WHERE id = ?', (id,))",
        "CWE-89", {"python"}, "high"
    ),
    (
        "INJ002", "Shell injection risk",
        r"""(?:subprocess\.(?:call|run|Popen)|os\.(?:system|popen))\s*\(.*shell\s*=\s*True""",
        Severity.HIGH, Category.INJECTION,
        "Shell command execution with shell=True enables injection attacks.",
        "Use subprocess with shell=False and pass arguments as a list.",
        "CWE-78", {"python"}, "high"
    ),
    (
        "INJ003", "Command injection via template",
        r"""os\.system\s*\(\s*(?:f['"]|['"].*%|['"].*\+|['"].*\.format)""",
        Severity.CRITICAL, Category.INJECTION,
        "OS command constructed from user-controlled input.",
        "Use subprocess.run() with shell=False and argument lists.",
        "CWE-78", {"python"}, "high"
    ),
    (
        "INJ004", "eval() usage",
        r"""\beval\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "eval() executes arbitrary code and is a major security risk.",
        "Use ast.literal_eval() for safe evaluation, or redesign to avoid eval entirely.",
        "CWE-95", {"python", "javascript", "typescript"}, "medium"
    ),
    (
        "INJ005", "Unsafe deserialization",
        r"""(?:pickle\.loads?|yaml\.(?:load|unsafe_load))\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "Unsafe deserialization can execute arbitrary code.",
        "Use yaml.safe_load() or json.loads() instead.",
        "CWE-502", {"python"}, "high"
    ),
    (
        "INJ006", "innerHTML assignment",
        r"""\.innerHTML\s*=(?!=)""",
        Severity.MEDIUM, Category.INJECTION,
        "Direct innerHTML assignment can lead to XSS.",
        "Use textContent for text, or sanitize HTML with DOMPurify.",
        "CWE-79", {"javascript", "typescript"}, "medium"
    ),
    (
        "INJ007", "SQL string concatenation",
        r"""(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*(?:req\.|request\.|params\.|query\.)""",
        Severity.HIGH, Category.INJECTION,
        "SQL query built with string concatenation from request data.",
        "Use parameterized queries or an ORM.",
        "CWE-89", {"javascript", "typescript"}, "high"
    ),
    (
        "INJ008", "Exec/Function constructor",
        r"""new\s+Function\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "Function constructor creates code from strings, similar to eval().",
        "Refactor to use standard function definitions.",
        "CWE-95", {"javascript", "typescript"}, "high"
    ),
    (
        "INJ009", "Go SQL injection",
        r"""(?:db\.(?:Query|Exec|QueryRow))\s*\(\s*(?:fmt\.Sprintf|.*\+)""",
        Severity.HIGH, Category.INJECTION,
        "SQL query built with string formatting in Go.",
        "Use parameterized queries: db.Query(\"SELECT * FROM t WHERE id = $1\", id)",
        "CWE-89", {"go"}, "high"
    ),
]

REQUEST_FORGERY = [
    # ── SSRF (Server-Side Request Forgery) ──
    (
        "SSRF001", "Potential SSRF via requests library",
        r"""requests\.(?:get|post|put|delete|patch|head)\s*\(\s*(?:f['"]|.*\+\s*(?:request|req|params|args)|.*\.format\()""",
        Severity.HIGH, Category.SECURITY,
        "HTTP request with user-controlled URL may enable Server-Side Request Forgery (SSRF).",
        "Validate and allowlist target URLs/hosts. Use a URL parser to verify the scheme and host.",
        "CWE-918", {"python"}, "medium"
    ),
    (
        "SSRF002", "Potential SSRF via fetch/axios",
        r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*(?:`.*\$\{|.*\+\s*(?:req\.|request\.|params\.|query\.|body\.))""",
        Severity.HIGH, Category.SECURITY,
        "HTTP request constructed from user input may enable SSRF attacks.",
        "Validate URLs against an allowlist of permitted hosts before making requests.",
        "CWE-918", {"javascript", "typescript"}, "medium"
    ),

    # ── Path Traversal ──
    (
        "PATH001", "Path traversal via user input",
        r"""(?:open|Path)\s*\(\s*(?:os\.path\.join\s*\(.*(?:request|req|params|args)|f['"].*(?:request|req|params|args))""",
        Severity.HIGH, Category.SECURITY,
        "File operation with user-controlled path may allow directory traversal attacks.",
        "Use os.path.realpath() and verify the resolved path is within the expected base directory.",
        "CWE-22", {"python"}, "medium"
    ),
    (
        "PATH002", "Path traversal in Node.js",
        r"""fs\.(?:readFile|writeFile|readdir|unlink|createReadStream|access)(?:Sync)?\s*\(\s*(?:req\.|request\.|params\.)""",
        Severity.HIGH, Category.SECURITY,
        "File system operation with user-controlled path enables path traversal.",
        "Use path.resolve() and verify the result starts with the intended base directory.",
        "CWE-22", {"javascript", "typescript"}, "medium"
    ),
]

REDIRECTS = [
    # ── Open Redirect ──
    (
        "REDIR001", "Open redirect in Python web framework",
        r"""(?:redirect|HttpResponseRedirect|RedirectResponse)\s*\(\s*(?:request\.|req\.|params\[|args\.)""",
        Severity.MEDIUM, Category.SECURITY,
        "Redirect using user-controlled input may allow open redirect attacks.",
        "Validate redirect targets against an allowlist of permitted URLs.",
        "CWE-601", {"python"}, "medium"
    ),
    (
        "REDIR002", "Open redirect in Express",
        r"""res\.redirect\s*\(\s*(?:req\.(?:query|params|body)\[|req\.(?:query|params|body)\.)""",
        Severity.MEDIUM, Category.SECURITY,
        "Express redirect using user-supplied input enables open redirect.",
        "Validate redirect URLs against an allowlist of permitted paths or hosts.",
        "CWE-601", {"javascript", "typescript"}, "medium"
    ),
]

TEMPLATES = [
    # ── Template Injection (SSTI) ──
    (
        "SSTI001", "Server-side template injection",
        r"""render_template_string\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "render_template_string() renders templates from strings, enabling server-side template injection if user input is included.",
        "Use render_template() with static template files instead of render_template_string().",
        "CWE-1336", {"python"}, "medium"
    ),
]

BROWSER_MARKUP = [
    # ── React / Frontend XSS ──
    (
        "REACT001", "dangerouslySetInnerHTML usage",
        r"""dangerouslySetInnerHTML""",
        Severity.MEDIUM, Category.INJECTION,
        "dangerouslySetInnerHTML bypasses React's built-in XSS protections.",
        "Sanitize HTML with DOMPurify before using dangerouslySetInnerHTML.",
        "CWE-79", {"javascript", "typescript"}, "medium"
    ),
    (
        "REACT002", "javascript: URI in href",
        r"""href\s*=\s*['"]javascript:""",
        Severity.HIGH, Category.INJECTION,
        "javascript: URIs in href attributes execute arbitrary code (XSS).",
        "Validate URLs and reject javascript: protocol. Allow only http: and https: schemes.",
        "CWE-79", {"javascript", "typescript"}, "high"
    ),
    (
        "JS001", "document.write() usage",
        r"""document\.write\s*\(""",
        Severity.MEDIUM, Category.INJECTION,
        "document.write() can introduce XSS vulnerabilities and blocks page rendering.",
        "Use DOM APIs (createElement, textContent) instead of document.write().",
        "CWE-79", {"javascript", "typescript"}, "medium"
    ),
]

WEB_FRAMEWORKS = [
    # ── Django-Specific ──
    (
        "DJANGO001", "Django mark_safe with variable input",
        r"""mark_safe\s*\(\s*(?:f['"]|.*\+|.*\.format\(|.*%)""",
        Severity.HIGH, Category.INJECTION,
        "mark_safe() with dynamic content bypasses Django's auto-escaping, enabling XSS.",
        "Use format_html() instead of mark_safe() with string formatting.",
        "CWE-79", {"python"}, "high"
    ),
    (
        "DJANGO002", "Django raw SQL query",
        r"""(?:\.raw|\.extra|RawSQL)\s*\(\s*(?:f['"]|['"].*\.format\()""",
        Severity.HIGH, Category.INJECTION,
        "Django raw SQL query with string formatting enables SQL injection.",
        "Use Django ORM or pass parameters: Model.objects.raw('SELECT ... WHERE id = %s', [id]).",
        "CWE-89", {"python"}, "high"
    ),

    # ── Flask-Specific ──
    (
        "FLASK001", "Flask SECRET_KEY hardcoded",
        r"""(?:app\.secret_key|config\s*\[\s*['"]SECRET_KEY['"]\s*\])\s*=\s*['"][^'"]+['"]""",
        Severity.CRITICAL, Category.SECRET,
        "Flask SECRET_KEY is hardcoded. This compromises session security.",
        "Load SECRET_KEY from environment variable: app.secret_key = os.environ['SECRET_KEY'].",
        "CWE-798", {"python"}, "high"
    ),
    (
        "FLASK002", "Flask send_file path traversal",
        r"""send_file\s*\(\s*(?:request\.|os\.path\.join\s*\(.*request\.)""",
        Severity.HIGH, Category.SECURITY,
        "send_file() with user-controlled path enables arbitrary file read.",
        "Use send_from_directory() with a fixed base directory instead.",
        "CWE-22", {"python"}, "high"
    ),

    # ── Node.js / Express ──
    (
        "JS002", "Command injection via child_process",
        r"""child_process\.(?:exec|execSync)\s*\(\s*(?:`.*\$\{|.*\+\s*(?:req|request|params|query|body))""",
        Severity.CRITICAL, Category.INJECTION,
        "Command executed with user-controlled input enables remote code execution.",
        "Use execFile/execFileSync with arguments as an array. Never concatenate user input into commands.",
        "CWE-78", {"javascript", "typescript"}, "high"
    ),
]

DESERIALIZATION = [
    (
        "PY003", "Unsafe marshal/shelve deserialization",
        r"""(?:marshal\.loads?|shelve\.open)\s*\(""",
        Severity.HIGH, Category.INJECTION,
        "marshal and shelve can execute arbitrary code during deserialization.",
        "Use json.loads() for untrusted data. Only use marshal/shelve with trusted sources.",
        "CWE-502", {"python"}, "medium"
    ),
]
