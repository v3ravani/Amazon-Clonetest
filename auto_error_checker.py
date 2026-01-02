#!/usr/bin/env python3
"""
Universal Static Error & Security Checker
Works across most languages using static heuristics.
Creates a GitHub Issue if problems are found.
"""

import os
import sys
import json
import hashlib
import re
import subprocess
import urllib.request
import xml.etree.ElementTree as ET

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = os.getenv("GITHUB_REPOSITORY")

IGNORED_DIRS = {
    ".git", ".github", "__pycache__", "node_modules",
    "venv", "env", "dist", "build", ".idea", ".vscode"
}

ERRORS = []
CODE_BLOCKS = {}

# --------------------------------------------------
# 🔍 REGEX RULE SETS
# --------------------------------------------------

API_KEY_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",                # AWS
    r"AIza[0-9A-Za-z\-_]{35}",          # Google
    r"sk_live_[0-9a-zA-Z]{24}",          # Stripe
    r"eyJ[a-zA-Z0-9_-]+\.eyJ",           # JWT
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
    r"base64\.b64decode",
]

BACKDOOR_PATTERNS = [
    r"__import__",
    r"compile\(",
    r"globals\(",
]

OPEN_ENDPOINT_PATTERNS = [
    r"0\.0\.0\.0",
    r"app\.run\(.*debug\s*=\s*True",
    r"@app\.route\(.+\)",
]

BROKEN_LOOP_PATTERNS = [
    r"while\s*\(\s*true\s*\)",
    r"while\s+True\s*:",
]

# --------------------------------------------------
# 🔎 FILE ANALYSIS
# --------------------------------------------------

def record_error(msg):
    ERRORS.append(msg)

def hash_block(text):
    return hashlib.sha256(text.encode()).hexdigest()

def analyze_text(file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        record_error(f"Encoding error in {file}")
        return

    # --- Hard‑coded secrets ---
    for p in API_KEY_PATTERNS:
        if re.search(p, content):
            record_error(f"Hard‑coded API key detected in {file}")

    # --- Plain passwords ---
    for p in PASSWORD_PATTERNS:
        if re.search(p, content, re.IGNORECASE):
            record_error(f"Unencrypted password in {file}")

    # --- Dangerous code ---
    for p in DANGEROUS_PATTERNS:
        if re.search(p, content):
            record_error(f"Dangerous code usage `{p}` in {file}")

    # --- Backdoors ---
    for p in BACKDOOR_PATTERNS:
        if re.search(p, content):
            record_error(f"Possible backdoor pattern `{p}` in {file}")

    # --- Open endpoints ---
    for p in OPEN_ENDPOINT_PATTERNS:
        if re.search(p, content):
            record_error(f"Open / insecure endpoint detected in {file}")

    # --- Broken loops ---
    for p in BROKEN_LOOP_PATTERNS:
        if re.search(p, content):
            record_error(f"Potential infinite loop in {file}")

    # --- Code duplication ---
    lines = [l.strip() for l in content.splitlines() if l.strip()]
    block = "\n".join(lines[:50])
    h = hash_block(block)
    if h in CODE_BLOCKS:
        record_error(f"Code duplication between {file} and {CODE_BLOCKS[h]}")
    else:
        CODE_BLOCKS[h] = file

# --------------------------------------------------
# 🧠 DEAD CODE (PYTHON HEURISTIC)
# --------------------------------------------------

def check_dead_code(file):
    try:
        output = subprocess.run(
            [sys.executable, "-m", "py_compile", file],
            stderr=subprocess.PIPE,
        )
        if output.stderr:
            record_error(f"Python error in {file}:\n{output.stderr.decode()}")
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
