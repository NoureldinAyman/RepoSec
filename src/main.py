import argparse
from src.features.commit_history.history_scanner import scan_git_history


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

        if not findings:
            print("No secrets found in git history.")
        else:
            print(f"Found {len(findings)} potential secrets in git history:")
            for f in findings:
                print(
                    f"- {f.commit[:8]}  {f.file}  [{f.rule}]  {f.preview}"
                )

    elif args.command == "scan-deps":
        print("Dependency vulnerability scanning not implemented yet.")

    else:
        print(f"Unknown command: {args.command}")


if __name__ == "__main__":
    main()
