import argparse
from src.features.commit_history.history_scanner import scan_git_history, export_history_findings_json

<<<<<<< HEAD
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
=======
def main():
    parser = argparse.ArgumentParser(
        prog="reposec",
        description="RepoSec - Cybersecurity scanning tool"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "scan-history",
        help="Scan git commit history for leaked secrets"
    )

    sub.add_parser(
        "scan-deps",
        help="Scan dependency files for known vulnerabilities"
    )

    args = parser.parse_args()

    if args.command == "scan-history":
        findings = scan_git_history()
        export_history_findings_json(findings, "reports/history_findings.json")

        if not findings:
            print("No secrets found in git history.")
        else:
            print(f"Found {len(findings)} potential secrets in git history:")
            for f in findings:
                print(
                    f"- {f.commit[:8]}  {f.file}  [{f.rule}]  {f.preview}"
                )

    elif args.command == "scan-deps":
        print("Saved report to reports/history_findings.json")
    else:
        print(f"Unknown command: {args.command}")
>>>>>>> main


if __name__ == "__main__":
    main()
