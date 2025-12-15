from pathlib import Path
from src.features.dependency_vuln.dep_checker import parse_requirements_txt


def test_parse_pinned_requirements(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.32.3\n# comment\npytest==8.4.1\n", encoding="utf-8")

    deps = parse_requirements_txt(str(req))
    assert len(deps) == 2
    assert deps[0].name == "requests"
    assert deps[0].version == "2.32.3"
