import sys
import requests

API = "https://api.github.com"

SKIP_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib",
    ".mp3", ".mp4", ".mov", ".avi",
}

def list_repos(username):
    # Fetch public repositories for a GitHub username.
    url = f"{API}/users/{username}/repos"
    r = requests.get(url, params={"per_page": 100})
    r.raise_for_status()
    return r.json()


def list_contents(owner, repo, path=""):
    # Fetch files/folders at a given path inside a GitHub repository.
    url = f"{API}/repos/{owner}/{repo}/contents/{path}".rstrip("/")
    r = requests.get(url)
    r.raise_for_status()
    return r.json()


def should_scan(path):
    # Decide if a path looks like a useful text/code file.
    lower = path.lower()

    # Skip obvious vendor/build dirs (cheap win).
    if "/node_modules/" in lower or "/dist/" in lower or "/build/" in lower:
        return False

    dot = lower.rfind(".")
    ext = lower[dot:] if dot != -1 else ""

    if ext in SKIP_EXTS:
        return False

    # If you want strict allow-list behavior, uncomment this:
    # if ext and ext not in ALLOW_EXTS:
    #     return False

    return True


def walk_repo(owner, repo, path=""):
    # Recursively walk a repo directory and print file paths we want to scan.
    items = list_contents(owner, repo, path)

    if isinstance(items, dict) and items.get("type") == "file":
        if should_scan(items["path"]):
            print(f"{owner}/{repo}:{items['path']}")
        return

    for item in items:
        if item["type"] == "file":
            if should_scan(item["path"]):
                print(f"{owner}/{repo}:{item['path']}")
        elif item["type"] == "dir":
            walk_repo(owner, repo, item["path"])


def main():
    # Read username from argv, then traverse all public repos for that user.
    if len(sys.argv) != 2:
        print("Usage: python traverse_user_repos.py <github_username>")
        return

    username = sys.argv[1]
    repos = list_repos(username)

    for repo in repos:
        owner = repo["owner"]["login"]
        name = repo["name"]

        print(f"\n== {owner}/{name} ==")
        try:
            walk_repo(owner, name)
        except requests.HTTPError as e:
            print(f"  [skip] {e}")


if __name__ == "__main__":
    main()
