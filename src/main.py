import argparse

from src.features.dependency_vuln.dep_checker import (
    scan_requirements_for_vulns,
    export_deps_findings_json,
)


def main():
    parser = argparse.ArgumentParser(
        prog="reposec",
        description="RepoSec - Cybersecurity scanning tool"
    )

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("scan-deps", help="Check requirements.txt dependencies for known vulnerabilities (OSV)")

    args = parser.parse_args()

    if args.command == "scan-deps":
        matches = scan_requirements_for_vulns()
        export_deps_findings_json(matches, "reports/deps_findings.json")

        if not matches:
            print("No known vulnerable dependencies found (based on OSV).")
        else:
            print(f"Found {len(matches)} vulnerable dependency matches:")
            for m in matches:
                print(f"- {m.dependency.name}=={m.dependency.version}  [{m.vuln_id}]  {m.summary}")

        print("Saved report to reports/deps_findings.json")


if __name__ == "__main__":
    main()
