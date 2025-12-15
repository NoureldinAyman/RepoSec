from dataclasses import dataclass
from pathlib import Path
import re
from typing import List
import requests


@dataclass
class Dependency:
    name: str
    version: str


REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9_.+-]+)\s*$")


def parse_requirements_txt(path: str = "requirements.txt") -> List[Dependency]:
    """
    Parse pinned dependencies of the form: package==version
    Ignores comments, blank lines, and non-pinned entries.
    """
    p = Path(path)
    if not p.exists():
        return []

    deps: List[Dependency] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = REQ_LINE.match(line)
        if not m:
            # Skip non-pinned lines like "flask>=2" or "-e ." to keep MVP simple
            continue
        deps.append(Dependency(name=m.group(1), version=m.group(2)))
    return deps

@dataclass
class VulnMatch:
    dependency: Dependency
    vuln_id: str
    summary: str


def query_osv_for_dependency(dep: Dependency) -> list[VulnMatch]:
    """
    Query OSV.dev for vulnerabilities affecting a specific package version.
    Ecosystem: PyPI (since we're parsing requirements.txt).
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": dep.version,
        "package": {"name": dep.name, "ecosystem": "PyPI"},
    }

    r = requests.post(url, json=payload, timeout=20)
    r.raise_for_status()
    data = r.json()

    matches: list[VulnMatch] = []
    for v in data.get("vulns", []):
        vid = v.get("id", "UNKNOWN")
        summary = v.get("summary") or v.get("details", "")
        summary = summary.strip().replace("\n", " ")
        if len(summary) > 120:
            summary = summary[:120] + "..."
        matches.append(VulnMatch(dependency=dep, vuln_id=vid, summary=summary))

    return matches

def scan_requirements_for_vulns(path: str = "requirements.txt") -> list[VulnMatch]:
    deps = parse_requirements_txt(path)
    all_matches: list[VulnMatch] = []
    for dep in deps:
        all_matches.extend(query_osv_for_dependency(dep))
    return all_matches
