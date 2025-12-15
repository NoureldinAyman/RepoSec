from dataclasses import dataclass
from pathlib import Path
import re
from typing import List


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
