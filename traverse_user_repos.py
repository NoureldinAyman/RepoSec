import os
import time
import requests

API = "https://api.github.com"

SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".mp3", ".mp4", ".mov", ".avi",
}


def gh_get(url, params=None):
    # GET helper with optional token + basic rate limit handling.
    headers = {"Accept": "application/vnd.github+json"}

    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    r = requests.get(url, params=params, headers=headers, timeout=30)

    if r.status_code == 403 and r.headers.get("X-RateLimit-Remaining") == "0":
        reset = int(r.headers.get("X-RateLimit-Reset", "0"))
        wait = max(1, reset - int(time.time()))
        print(f"[rate-limit] waiting {wait}s...")
        time.sleep(wait)
        r = requests.get(url, params=params, headers=headers, timeout=30)

    r.raise_for_status()
    return r


def list_repos(username):
    # Get public repositories for a GitHub username.
    url = f"{API}/users/{username}/repos"
    r = gh_get(url, params={"per_page": 100})
    return r.json()


def list_contents(owner, repo, path="", branch=None):
    # Get repo contents at a path, optionally for a specific branch.
    url = f"{API}/repos/{owner}/{repo}/contents/{path}".rstrip("/")
    params = {"ref": branch} if branch else None
    r = gh_get(url, params=params)
    return r.json()


def should_scan(path):
    # Basic filter for binaries and common build/vendor folders.
    lower = path.lower()

    if "/node_modules/" in lower or "/dist/" in lower or "/build/" in lower:
        return False

    dot = lower.rfind(".")
    ext = lower[dot:] if dot != -1 else ""

    return ext not in SKIP_EXTS


def iter_repo_files(owner, repo, path="", branch=None):
    # Yield file items by walking repo directories.
    items = list_contents(owner, repo, path, branch=branch)

    if isinstance(items, dict) and items.get("type") == "file":
        items = [items]

    for item in items:
        if item.get("type") == "dir":
            yield from iter_repo_files(owner, repo, item["path"], branch=branch)
        elif item.get("type") == "file":
            yield item
