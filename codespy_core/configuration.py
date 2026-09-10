"""Scanner identity, the file types it reads, and the limits of one scan."""

__version__ = "1.1.0"
__author__ = "Adam (ADAM) — Wisent AI Agent"

# File extensions to scan by language
LANGUAGE_EXTENSIONS = {
    "python": {".py", ".pyw"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "go": {".go"},
    "rust": {".rs"},
    "java": {".java"},
    "ruby": {".rb"},
    "php": {".php"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".hpp", ".cc", ".cxx"},
    "csharp": {".cs"},
    "shell": {".sh", ".bash", ".zsh"},
    "yaml": {".yml", ".yaml"},
    "dockerfile": {"Dockerfile"},
    "terraform": {".tf"},
    "sql": {".sql"},
}

# Directories to always skip
SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".tox",
    ".pytest_cache", ".mypy_cache", "venv", ".venv", "env", ".env",
    "vendor", "dist", "build", ".next", ".nuxt", "target",
    "coverage", ".coverage", "htmlcov", ".eggs", "*.egg-info",
}

MAX_FILE_SIZE = 1_000_000  # 1MB max per file
