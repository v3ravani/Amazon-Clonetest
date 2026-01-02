#!/usr/bin/env python3
"""
Universal GitHub Repo Error Checker
Works for most known languages.
Creates a GitHub Issue if errors are found.
"""

import os
import sys
import json
import subprocess
import urllib.request
import urllib.error
import xml.etree.ElementTree as ET

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO = os.getenv("GITHUB_REPOSITORY")

IGNORED_DIRS = {
    ".git", ".github", "__pycache__", "node_modules",
    "venv", "env", "dist", "build", ".idea", ".vscode"
}

ERRORS = []

# ---------- Language Checks ----------

def run_cmd(cmd, file):
    try:
        subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        ERRORS.append(f"{file}:\n{e.stderr.decode(errors='ignore')}")

def check_python(file):
    run_cmd([sys.executable, "-m", "py_compile", file], file)

def check_javascript(file):
    run_cmd(["node", "--check", file], file)

def check_typescript(file):
    run_cmd(["npx", "tsc", "--noEmit", file], file)

def check_go(file):
    run_cmd(["go", "vet", file], file)

def check_java(file):
    run_cmd(["javac", file], file)

def check_c_cpp(file):
    run_cmd(["gcc", "-fsyntax-only", file], file)

def check_json(file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            json.load(f)
    except Exception as e:
        ERRORS.append(f"JSON error in {file}: {e}")

def check_xml(file):
    try:
        ET.parse(file)
    except Exception as e:
        ERRORS.append(f"XML error in {file}: {e}")

def check_yaml(file):
    try:
        import yaml
        with open(file, "r", encoding="utf-8") as f:
            yaml.safe_load(f)
    except ImportError:
        pass
    except Exception as e:
        ERRORS.append(f"YAML error in {file}: {e}")

def check_shell(file):
    run_cmd(["bash", "-n", file], file)

def check_text(file):
    try:
        with open(file, "r", encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                if line.rstrip("\n").endswith(" "):
                    ERRORS.append(f"Trailing whitespace: {file}:{i}")
                if "TODO" in line or "FIXME" in line:
                    ERRORS.append(f"TODO/FIXME found: {file}:{i}")
    except Exception:
        ERRORS.append(f"Encoding error in {file}")

# ---------- File Walker ----------

def scan_repo():
    for root, dirs, files in os.walk("."):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]
        for name in files:
            path = os.path.join(root, name)

            if path.startswith("./."):
                continue

            try:
                if name.endswith(".py"):
                    check_python(path)
                elif name.endswith(".js"):
                    check_javascript(path)
                elif name.endswith(".ts"):
                    check_typescript(path)
                elif name.endswith(".go"):
                    check_go(path)
                elif name.endswith(".java"):
                    check_java(path)
                elif name.endswith((".c", ".cpp")):
                    check_c_cpp(path)
                elif name.endswith(".json"):
                    check_json(path)
                elif name.endswith((".yml", ".yaml")):
                    check_yaml(path)
                elif name.endswith(".xml"):
                    check_xml(path)
                elif name.endswith(".sh"):
                    check_shell(path)
                else:
                    check_text(path)
            except Exception as e:
                ERRORS.append(f"Unhandled error in {path}: {e}")

# ---------- GitHub Issue Creator ----------

def create_issue(report):
    if not GITHUB_TOKEN or not REPO:
        print("Missing GitHub environment variables.")
        return

    url = f"https://api.github.com/repos/{REPO}/issues"
    payload = {
        "title": "🚨 Automatic Repository Error Report",
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
    except urllib.error.HTTPError as e:
        print("Issue creation failed:", e.read().decode())

# ---------- Main ----------

if __name__ == "__main__":
    scan_repo()

    if ERRORS:
        body = "## ❌ Errors detected by automatic checker\n\n"
        body += "\n\n".join(f"- {e}" for e in ERRORS)
        create_issue(body)
        print("Errors found. Issue created.")
        sys.exit(1)

    print("✅ No errors found.")
