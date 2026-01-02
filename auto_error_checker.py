#!/usr/bin/env python3
"""
Universal Language-Inclusive Static Analyzer
CI-ready | Binary-safe | Line-number aware
"""

import os
import sys
import json
import re
import hashlib
import subprocess
import urllib.request

# --------------------------------------------------
# ENV
# --------------------------------------------------

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = os.getenv("GITHUB_REPOSITORY")

# --------------------------------------------------
# FILTERS
# --------------------------------------------------

IGNORED_DIRS = {
    ".git", ".github", "__pycache__", "node_modules",
    "venv", "env", "dist", "build", ".idea", ".vscode"
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".ttf", ".otf", ".woff", ".woff2",
    ".mp3", ".mp4", ".avi", ".mov"
}

LANGUAGE_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".dart": "dart",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".sh": "shell",
    ".kt": "kotlin",
    ".rs": "rust",
}

# --------------------------------------------------
# RULES
# --------------------------------------------------

RULES = {
    "API_KEY": [
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z\-_]{35}",
        r"sk_live_[0-9a-zA-Z]{24}",
        r"eyJ[a-zA-Z0-9_-]+\.eyJ",
    ],
    "PASSWORD": [
        r"password\s*=\s*['\"].+['\"]",
        r"passwd\s*=\s*['\"].+['\"]",
        r"pwd\s*=\s*['\"].+['\"]",
    ],
    "DANGEROUS": [
        r"os\.system",
        r"subprocess",
        r"exec\(",
        r"eval\(",
        r"Process\.run",
        r"Runtime\.getRuntime",
    ],
    "BACKDOOR": [
        r"__import__",
        r"compile\(",
        r"globals\(",
        r"base64",
    ],
    "OPEN_ENDPOINT": [
        r"0\.0\.0\.0",
        r"app\.run\(.*debug\s*=\s*True",
        r"listen\(\d+,\s*['\"]0\.0\.0\.0",
    ],
    "BROKEN_LOOP": [
        r"while\s*\(\s*true\s*\)",
        r"while\s+True\s*:",
        r"for\s*\(;;\)",
    ],
}

# --------------------------------------------------
# STORAGE
# --------------------------------------------------

ERRORS = []
CODE_BLOCKS = {}

# --------------------------------------------------
# HELPERS
# --------------------------------------------------

def is_binary(path):
    return os.path.splitext(path.lower())[1] in BINARY_EXTENSIONS

def language_of(path):
    return LANGUAGE_MAP.get(os.path.splitext(path)[1].lower(), "unknown")

def record(file, line, message):
    ERRORS.append(f"{file}:{line} → {message}")

def hash_block(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

# --------------------------------------------------
# ANALYSIS
# --------------------------------------------------

def analyze_file(path):
    if is_binary(path):
        return

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return

    language = language_of(path)
    content = "".join(lines)

    # --- Line-by-line checks ---
    for idx, line in enumerate(lines, start=1):
        for rule, patterns in RULES.items():
            for p in patterns:
                if re.search(p, line, re.IGNORECASE):
                    record(
                        path,
                        idx,
                        f"[{language}] {rule.replace('_',' ').title()} detected"
                    )

    # --- Code duplication ---
    stripped = [l.strip() for l in lines if l.strip()]
    if len(stripped) >= 12:
        block = "\n".join(stripped[:40])
        h = hash_block(block)
        if h in CODE_BLOCKS:
            record(
                path,
                1,
                f"[{language}] Code duplication with {CODE_BLOCKS[h]}"
            )
        else:
            CODE_BLOCKS[h] = path

    # --- Python-specific checks ---
    if language == "python":
        python_syntax_check(path)

# --------------------------------------------------
# PYTHON DEAD CODE / SYNTAX
# --------------------------------------------------

def python_syntax_check(path):
    result = subprocess.run(
        [sys.executable, "-m", "py_compile", path],
        stderr=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
    )
    if result.stderr:
        msg = result.stderr.decode(errors="ignore").strip().splitlines()[-1]
        record(path, "?", f"[python] Syntax error → {msg}")

# --------------------------------------------------
# WALK REPO
# --------------------------------------------------

def scan_repo():
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for name in files:
            path = os.path.join(root, name)
            if path.startswith("./."):
                continue
            analyze_file(path)

# --------------------------------------------------
# GITHUB ISSUE
# --------------------------------------------------

def create_issue(body):
    if not GITHUB_TOKEN or not REPO:
        print("GitHub environment missing.")
        return

    req = urllib.request.Request(
        f"https://api.github.com/repos/{REPO}/issues",
        data=json.dumps({
            "title": "🚨 CI Static Analysis Report (Line-Level)",
            "body": body
        }).encode(),
        headers={
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json",
        }
    )

    try:
        urllib.request.urlopen(req)
    except Exception as e:
        print("Issue creation failed:", e)

# --------------------------------------------------
# MAIN
# --------------------------------------------------

if __name__ == "__main__":
    scan_repo()

    if ERRORS:
        report = "## ❌ Issues Detected (with line numbers)\n\n"
        report += "\n".join(f"- {e}" for e in ERRORS)
        create_issue(report)
        print("Errors found. Issue created.")
        sys.exit(1)

    print("✅ No issues found.")
