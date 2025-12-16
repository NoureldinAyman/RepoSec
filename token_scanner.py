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
    ("Stripe secret key", "HIGH", re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{16,}\b")),
    ("SendGrid API key", "HIGH", re.compile(r"\bSG\.[A-Za-z0-9_-]{20,}\b")),
    ("PyPI token", "HIGH", re.compile(r"\bpypi-[A-Za-z0-9]{20,}\b")),
    ("npm token", "HIGH", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
    ("Private key block header", "HIGH", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |)?PRIVATE KEY-----")),
    ("AWS Access Key ID", "MEDIUM", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Google API key", "MEDIUM", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
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


def scan_text(text, label, counters):
    # Scan content for matches, update counters, and return highest severity seen.
    highest = 0

    for line_no, line in enumerate(text.splitlines(), start=1):
        for name, sev, rx in PATTERNS:
            m = rx.search(line)
            if not m:
                continue

            highest = max(highest, severity_rank(sev))
            counters["hits_total"] += 1
            counters[f"hits_{sev.lower()}"] += 1

            val = m.group(0)
            shown = val if name.startswith("Private key block") else mask(val)
            print(f"[{sev}] {name} at {label}:{line_no}  value={shown}")

    return highest


def main():
    # Traverse repos, download files, scan, then print a summary.
    if len(sys.argv) < 2:
        print("Usage: python token_scanner.py <github_username> [--main-only]")
        return 2

    username = sys.argv[1]
    main_only = "--main-only" in sys.argv[2:]

    overall = {
        "repos": 0,
        "files_seen": 0,
        "files_scanned": 0,
        "skip_filtered": 0,
        "skip_large": 0,
        "skip_timeout": 0,
        "skip_connection": 0,
        "skip_http": 0,
        "hits_total": 0,
        "hits_high": 0,
        "hits_medium": 0,
        "hits_low": 0,
        "highest": 0,
    }

    repos = list_repos(username)

    for repo in repos:
        owner = repo["owner"]["login"]
        name = repo["name"]
        branch = "main" if main_only else repo.get("default_branch", "main")

        overall["repos"] += 1
        repo_counters = {
            "files_seen": 0,
            "files_scanned": 0,
            "skip_filtered": 0,
            "skip_large": 0,
            "skip_timeout": 0,
            "skip_connection": 0,
            "skip_http": 0,
            "hits_total": 0,
            "hits_high": 0,
            "hits_medium": 0,
            "hits_low": 0,
            "highest": 0,
        }

        print(f"\n== {owner}/{name} (branch: {branch}) ==")

        try:
            for item in iter_repo_files(owner, name, branch=branch):
                repo_counters["files_seen"] += 1

                path = item.get("path", "")
                if not should_scan(path):
                    repo_counters["skip_filtered"] += 1
                    continue

                download_url = item.get("download_url")
                if not download_url:
                    continue

                try:
                    text = fetch_text(download_url)
                except Timeout:
                    repo_counters["skip_timeout"] += 1
                    continue
                except ConnectionError:
                    repo_counters["skip_connection"] += 1
                    continue
                except requests.HTTPError:
                    repo_counters["skip_http"] += 1
                    continue

                if text is None:
                    repo_counters["skip_large"] += 1
                    continue

                repo_counters["files_scanned"] += 1
                highest = scan_text(text, f"{owner}/{name}:{path}", repo_counters)
                repo_counters["highest"] = max(repo_counters["highest"], highest)

        except requests.HTTPError as e:
            print(f"  [skip repo] {e}")

        # Roll repo counters into overall counters
        for k, v in repo_counters.items():
            if k in overall:
                overall[k] += v
        overall["highest"] = max(overall["highest"], repo_counters["highest"])

        print(
            f"  scanned={repo_counters['files_scanned']} "
            f"skipped={repo_counters['skip_filtered'] + repo_counters['skip_large'] + repo_counters['skip_timeout'] + repo_counters['skip_connection'] + repo_counters['skip_http']} "
            f"hits(H/M/L)={repo_counters['hits_high']}/{repo_counters['hits_medium']}/{repo_counters['hits_low']}"
        )

    # Overall summary
    print("\n=== Summary ===")
    print(f"repos:         {overall['repos']}")
    print(f"files seen:    {overall['files_seen']}")
    print(f"files scanned: {overall['files_scanned']}")
    print(
        "skipped:       "
        f"filtered={overall['skip_filtered']} "
        f"large={overall['skip_large']} "
        f"timeout={overall['skip_timeout']} "
        f"conn={overall['skip_connection']} "
        f"http={overall['skip_http']}"
    )
    print(f"hits:          total={overall['hits_total']} high={overall['hits_high']} medium={overall['hits_medium']} low={overall['hits_low']}")

    # Fail (non-zero) if any HIGH hit was found.
    return 1 if overall["hits_high"] > 0 else 0


if __name__ == "__main__":
    raise SystemExit(main())
