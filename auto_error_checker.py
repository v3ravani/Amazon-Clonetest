#!/usr/bin/env python3
"""
Language-Inclusive Static Code Analyzer
Supports multiple languages via adapters.
Binary-safe. CI-ready. GitHub Issues integration.
"""

import os
import sys
import json
import re
import hashlib
import subprocess
import urllib.request

# --------------------------------------------------
# 🔧 ENV
# --------------------------------------------------

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = os.getenv("GITHUB_REPOSITORY")

# --------------------------------------------------
# 📁 FILTERS
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

# --------------------------------------------------
# 🌍 LANGUAGE MAP (EXTENSION → LANGUAGE)
# --------------------------------------------------

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
# 🔍 RULE SETS (LANGUAGE-AGNOSTIC)
# --------------------------------------------------

API_KEY_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"AIza[0-9A-Za-z\-_]{35}",
    r"sk_live_[0-9a-zA-Z]{24}",
    r"eyJ[a-zA-Z0-9_-]+\.eyJ",
]

PASSWORD_PATTERNS = [
    r"password\s*=\s*['\"].+['\"]",
    r"passwd\s*=\s*['\"].+['\"]",
    r"pwd\s*=\s*['\"].+['\"]",
]

DANGEROUS_PATTERNS = [
    r"os\.system",
    r"subprocess",
    r"exec\(",
    r"eval\(",
    r"Process\.run",
    r"Runtime\.getRuntime",
]

BACKDOOR_PATTERNS = [
    r"__import__",
    r"compile\(",
    r"globals\(",
    r"base64",
]

OPEN_ENDPOINT_PATTERNS = [
    r"0\.0\.0\.0",
    r"app\.run\(.*debug\s*=\s*True",
    r"listen\(\d+,\s*['\"]0\.0\.0\.0",
]

BROKEN_LOOP_PATTERNS = [
    r"while\s*\(\s*true\s*\)",
    r"while\s+True\s*:",
    r"for\s*\(;;\)",
]

# --------------------------------------------------
# 🧠 STORAGE
# --------------------------------------------------

ERRORS = []
CODE_BLOCKS = {}

# --------------------------------------------------
# 🔎 HELPERS
# --------------------------------------------------

def is_binary(path):
    return os.path.splitext(path.lower())[1] in BINARY_EXTENSIONS

def record(msg):
    ERRORS.append(msg)

def hash_block(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

def detect_language(path):
    return LANGUAGE_MAP.get(os.path.splitext(path)[1].lower(), "unknown")

# --------------------------------------------------
# 🔍 CORE ANALYSIS (ALL LANGUAGES)
# --------------------------------------------------

def analyze_file(path):
    if is_binary(path):
        return

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return

    language = detect_language(path)

    # --- Secrets ---
    for p in API_KEY_PATTERNS:
        if re.search(p, content):
            record(f"[{language}] Hard-coded API key in {path}")

    # --- Passwords ---
    for p in PASSWORD_PATTERNS:
        if re.search(p, content, re.IGNORECASE):
            record(f"[{language}] Plaintext password in {path}")

    # --- Dangerous code ---
    for p in DANGEROUS_PATTERNS:
        if re.search(p, content):
            record(f"[{language}] Dangerous code `{p}` in {path}")

    # --- Backdoors ---
    for p in BACKDOOR_PATTERNS:
        if re.search(p, content):
            record(f"[{language}] Possible backdoor pattern `{p}` in {path}")

    # --- Open endpoints ---
    for p in OPEN_ENDPOINT_PATTERNS:
        if re.search(p, content):
            record(f"[{language}] Open / insecure endpoint in {path}")

    # --- Broken loops ---
    for p in BROKEN_LOOP_PATTERNS:
        if re.search(p, content):
            record(f"[{language}] Potential infinite loop in {path}")

    # --- Duplication (language-agnostic) ---
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if len(lines) >= 12:
        block = "\n".join(lines[:40])
        h = hash_block(block)
        if h in CODE_BLOCKS:
            record(f"[{language}] Code duplication: {path} ↔ {CODE_BLOCKS[h]}")
        else:
            CODE_BLOCKS[h] = path

    # --- Language-specific hooks ---
    if language == "python":
        python_syntax_check(path)

# --------------------------------------------------
# 🐍 PYTHON-SPECIFIC CHECK
# --------------------------------------------------

def python_syntax_check(path):
    try:
        subprocess.run(
            [sys.executable, "-m", "py_compile", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
    except Exception:
        record(f"[python] Syntax error in {path}")

# --------------------------------------------------
# 📂 WALK REPO
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
# 🐙 GITHUB ISSUE
# --------------------------------------------------

def create_issue(report):
    if not GITHUB_TOKEN or not REPO:
        print("GitHub env missing, skipping issue creation.")
        return

    url = f"https://api.github.com/repos/{REPO}/issues"
    payload = {
        "title": "🚨 Language-Inclusive Static Analysis Report",
        "body": report
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
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
# 🚀 MAIN
# --------------------------------------------------

if __name__ == "__main__":
    scan_repo()

    if ERRORS:
        body = "## ❌ Issues Detected (Language-Inclusive Scan)\n\n"
        body += "\n".join(f"- {e}" for e in ERRORS)
        create_issue(body)
        print("Errors found. Issue created.")
        sys.exit(1)

    print("✅ No issues found.")
