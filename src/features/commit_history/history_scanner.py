import os
import json
import subprocess
import re
from dataclasses import dataclass

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

@dataclass
class HistoryFinding:
    commit: str
    file: str
    rule: str
    preview: str


# Very small MVP rule set (expand later if you want)
SECRET_RULES: list[tuple[str, re.Pattern]] = [
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("GENERIC_PASSWORD_ASSIGNMENT", re.compile(r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]")),
]


def scan_text_for_secrets(text: str) -> list[tuple[str, str]]:
    """
    Returns a list of (rule_name, preview) matches found in the given text.
    """
    findings: list[tuple[str, str]] = []
    for rule_name, pattern in SECRET_RULES:
        for m in pattern.finditer(text):
            snippet = m.group(0)
            if len(snippet) > 80:
                snippet = snippet[:80] + "..."
            findings.append((rule_name, snippet))
    return findings


def scan_git_history(max_commits: int | None = None) -> list[HistoryFinding]:
    """
    Scans git commit history for secrets that might have been committed and later removed.
    max_commits can be used to limit scanning (useful for quick testing).
    """
    findings: list[HistoryFinding] = []

    commits = get_all_commits()
    if max_commits is not None:
        commits = commits[:max_commits]

    for commit in commits:
        files = get_files_in_commit(commit)
        for file_path in files:
            # Skip obvious non-text / huge files (lightweight filters)
            lowered = file_path.lower()
            if lowered.endswith((".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".exe", ".dll", ".p12", ".pfx")):
                continue

            content = get_file_content_at_commit(commit, file_path)
            if not content:
                continue

            matches = scan_text_for_secrets(content)
            for rule_name, preview in matches:
                findings.append(HistoryFinding(commit=commit, file=file_path, rule=rule_name, preview=preview))

    return findings

def export_history_findings_json(findings: list[HistoryFinding], output_path: str) -> None:
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    data = {
        "feature": "commit_history",
        "count": len(findings),
        "findings": [
            {
                "commit": f.commit,
                "file": f.file,
                "rule": f.rule,
                "preview": f.preview,
            }
            for f in findings
        ],
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

