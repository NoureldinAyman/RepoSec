import subprocess


def _run_git_command(args: list[str]) -> str:
    """
    Run a git command and return stdout text. Raises RuntimeError on failure.
    """
    result = subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        err = (result.stderr or "").strip()
        raise RuntimeError(f"Git command failed: git {' '.join(args)}\n{err}")
    return result.stdout


def get_all_commits() -> list[str]:
    """
    Returns a list of all commit hashes in the repository.
    """
    out = _run_git_command(["rev-list", "--all"])
    commits = [c for c in out.strip().split("\n") if c.strip()]
    return commits


def get_files_in_commit(commit_hash: str) -> list[str]:
    """
    Returns a list of file paths that exist in the given commit.
    """
    out = _run_git_command(["ls-tree", "-r", "--name-only", commit_hash])
    files = [f for f in out.strip().split("\n") if f.strip()]
    return files

def get_file_content_at_commit(commit_hash: str, file_path: str) -> str | None:
    """
    Returns the file content as text for a given commit and file path.
    If the file cannot be read as text (binary) or doesn't exist, returns None.
    """
    try:
        out = _run_git_command(["show", f"{commit_hash}:{file_path}"])
    except RuntimeError:
        return None  # file missing in this commit or can't be read

    # Very basic "binary" check: if it contains null bytes, treat as binary
    if "\x00" in out:
        return None

    return out

