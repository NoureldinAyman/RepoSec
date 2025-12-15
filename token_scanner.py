import sys
import re
import requests
from requests.exceptions import Timeout, ConnectionError

from traverse_user_repos import list_repos, iter_repo_files, should_scan


PATTERNS = [
    ("Hugging Face token", "HIGH", re.compile(r"\bhf_[A-Za-z0-9]{20,}\b")),
    ("GitHub token (ghp_)", "HIGH", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("GitHub token (github_pat_)", "HIGH", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("GitLab token (glpat-)", "HIGH", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token (xox*)", "HIGH", re.compile(r"\bxox[baprsco]-[A-Za-z0-9-]{10,}\b")),
    ("AWS Access Key ID", "MEDIUM", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", "MEDIUM", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Stripe secret key", "HIGH", re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{16,}\b")),
    ("SendGrid API key", "HIGH", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\b")),
    ("PyPI token", "HIGH", re.compile(r"\bpypi-[A-Za-z0-9]{20,}\b")),
    ("npm token", "HIGH", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
    ("Private key block header", "HIGH", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----")),
]


def mask(s):
    # Hide most of a match so we don't print secrets in full.
    if len(s) <= 8:
        return "****"
    return s[:4] + "..." + s[-4:]


def fetch_text(url, max_bytes=2_000_000):
    # Download raw file content as text (skip very large files).
    r = requests.get(url, timeout=30)
    r.raise_for_status()

    if len(r.content) > max_bytes:
        return None

    return r.content.decode("utf-8", errors="replace")


def severity_rank(level):
    # Convert severity text to a comparable number.
    if level == "HIGH":
        return 3
    if level == "MEDIUM":
        return 2
    return 1


def scan_text(text, label):
    # Scan lines for regex matches and return highest severity found.
    highest = 0

    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, sev, rx in PATTERNS:
            m = rx.search(line)
            if not m:
                continue

            highest = max(highest, severity_rank(sev))
            val = m.group(0)

            shown = val if name.startswith("Private key block") else mask(val)
            print(f"[{sev}] {name} at {label}:{line_no}  value={shown}")

    return highest


def main():
    # Traverse a user's repos, download files, and run regex scanning.
    if len(sys.argv) < 2:
        print("Usage: python token_scanner.py <github_username> [--main-only]")
        return 2

    username = sys.argv[1]
    main_only = "--main-only" in sys.argv[2:]

    repos = list_repos(username)
    overall_highest = 0

    for repo in repos:
        owner = repo["owner"]["login"]
        name = repo["name"]

        branch = "main" if main_only else repo.get("default_branch", "main")
        print(f"\n== {owner}/{name} (branch: {branch}) ==")

        try:
            for item in iter_repo_files(owner, name, branch=branch):
                path = item.get("path", "")
                if not should_scan(path):
                    continue

                download_url = item.get("download_url")
                if not download_url:
                    continue

                try:
                    text = fetch_text(download_url)
                except (requests.HTTPError, Timeout, ConnectionError):
                    continue

                if text is None:
                    continue

                highest = scan_text(text, f"{owner}/{name}:{path}")
                overall_highest = max(overall_highest, highest)

        except requests.HTTPError as e:
            print(f"  [skip repo] {e}")

    # Exit non-zero if any HIGH severity was found.
    return 1 if overall_highest >= 3 else 0


if __name__ == "__main__":
    raise SystemExit(main())
