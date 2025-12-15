import subprocess


def get_all_commits():
    """
    Returns a list of all commit hashes in the repository.
    """
    result = subprocess.run(
        ["git", "rev-list", "--all"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        raise RuntimeError("Failed to retrieve git commit history")

    commits = result.stdout.strip().split("\n")
    return commits
