#!/usr/bin/env python3
"""
Universal Static Error & Security Checker
Binary-safe version (no encoding errors).
"""

import os
import sys
import json
import hashlib
import re
import subprocess
import urllib.request

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = os.getenv("GITHUB_REPOSITORY")

IGNORED_DIRS = {
    ".git", ".github", "__pycache__", "node_modules",
    "venv", "env", "dist", "build", ".idea", ".vscode"
}

# Binary / non-text extensions to skip completely
BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".ttf", ".otf", ".woff", ".woff2",
    ".mp3", ".mp4", ".avi", ".mov"
}

ERRORS = []
CODE_BLOCKS = {}

# --------------------------------------------------
# 🔍 REGEX RULE SETS
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
    r"subprocess\.Popen",
    r"eval\(",
    r"exec\(",
    r"pickle\.loads",
]

BACKDOOR_PATTERNS = [
    r"__import__",
    r"compile\(",
    r"globals\(",
]

OPEN_ENDPOINT_PATTERNS = [
    r"0\.0\.0\.0",
    r"app\.run\(.*debug\s*=\s*True",
    r"@app\.route\(",
]

BROKEN_LOOP_PATTERNS = [
    r"while\s*\(\s*true\s*\)",
    r"while\s+True\s*:",
]

# --------------------------------------------------
# 🔎 HELPERS
# --------------------------------------------------

def is_binary_file(path):
    _, ext = os.path.splitext(path.lower())
    return ext in BINARY_EXTENSIONS

def record_error(msg):
    ERRORS.append(msg)

def hash_block(text):
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

# --------------------------------------------------
# 🔍 TEXT ANALYSIS (SAFE)
# --------------------------------------------------

def analyze_text(file):
    if is_binary_file(file):
        return  # ✅ skip images & binaries completely

    try:
        with open(file, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return  # fully ignore unreadable files

    # Hard-coded API keys
    for p in API_KEY_PATTERNS:
        if re.search(p, content):
            record_error(f"Hard-coded API key detected in {file}")

    # Plain passwords
    for p in PASSWORD_PATTERNS:
        if re.search(p, content, re.IGNORECASE):
            record_error(f"Unencrypted password in {file}")

    # Dangerous code
    for p in DANGEROUS_PATTERNS:
        if re.search(p, content):
            record_error(f"Dangerous code `{p}` in {file}")

    # Backdoor patterns
    for p in BACKDOOR_PATTERNS:
        if re.search(p, content):
            record_error(f"Possible backdoor pattern `{p}` in {file}")

    # Open endpoints
    for p in OPEN_ENDPOINT_PATTERNS:
        if re.search(p, content):
            record_error(f"Open / insecure endpoint in {file}")

    # Broken loops
    for p in BROKEN_LOOP_PATTERNS:
        if re.search(p, content):
            record_error(f"Potential infinite loop in {file}")

    # Code duplication (first 40 non-empty lines)
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    if len(lines) >= 10:
        block = "\n".join(lines[:40])
        h = hash_block(block)
        if h in CODE_BLOCKS:
            record_error(f"Code duplication between {file} and {CODE_BLOCKS[h]}")
        else:
            CODE_BLOCKS[h] = file

# --------------------------------------------------
# 🧠 DEAD CODE (PYTHON ONLY)
# --------------------------------------------------

def check_dead_code(file):
    try:
        subprocess.run(
            [sys.executable, "-m", "py_compile", file],
            stderr=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
        )
    except Exception:
        pass

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

            analyze_text(path)

            if path.endswith(".py"):
                check_dead_code(path)

# --------------------------------------------------
# 🐙 GITHUB ISSUE CREATION
# --------------------------------------------------

def create_issue(report):
    if not GITHUB_TOKEN or not REPO:
        print("GitHub token or repo missing.")
        return

    url = f"https://api.github.com/repos/{REPO}/issues"
    payload = {
        "title": "🚨 Static Security & Code Analysis Report",
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
        body = "## ❌ Issues Detected\n\n"
        body += "\n".join(f"- {e}" for e in ERRORS)
        create_issue(body)
        print("Errors found. Issue created.")
        sys.exit(1)

    print("✅ No issues found.")
