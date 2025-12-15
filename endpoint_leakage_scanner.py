import sys
import requests
from requests.exceptions import Timeout, ConnectionError

from traverse_user_repos import list_repos, iter_repo_files, should_scan
from endpoint_extractors import extract_endpoints


def fetch_text(url, max_bytes=2_000_000):
    # Download raw file content as text (skip very large files).
    r = requests.get(url, timeout=30)
    r.raise_for_status()

    if len(r.content) > max_bytes:
        return None

    return r.content.decode("utf-8", errors="replace")


def print_hits(label, line_no, extracted):
    # Print extracted endpoints with file label and line number.
    for url in extracted["urls"]:
        print(f"[URL]  {label}:{line_no}  {url}")

    for ip in extracted["ipv4"]:
        print(f"[IP]   {label}:{line_no}  {ip}")

    for host in extracted["internal_hosts"]:
        print(f"[HOST] {label}:{line_no}  {host}")


def scan_text(text, label):
    # Extract endpoints line-by-line so we can report line numbers.
    for line_no, line in enumerate(text.splitlines(), start=1):
        extracted = extract_endpoints(line)

        if not extracted["urls"] and not extracted["ipv4"] and not extracted["internal_hosts"]:
            continue

        # Keep output a bit cleaner if the same thing appears twice on one line.
        extracted["urls"] = list(dict.fromkeys(extracted["urls"]))
        extracted["ipv4"] = list(dict.fromkeys(extracted["ipv4"]))
        extracted["internal_hosts"] = list(dict.fromkeys(extracted["internal_hosts"]))

        print_hits(label, line_no, extracted)


def main():
    # Scan a user's repos and print URL/IP/host candidates with line numbers.
    if len(sys.argv) < 2:
        print("Usage: python endpoint_leakage_scanner.py <github_username> [--main-only]")
        return 2

    username = sys.argv[1]
    main_only = "--main-only" in sys.argv[2:]

    repos = list_repos(username)

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

                scan_text(text, f"{owner}/{name}:{path}")

        except requests.HTTPError as e:
            print(f"  [skip repo] {e}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
