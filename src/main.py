import argparse

def main():
    parser = argparse.ArgumentParser(prog="reposec", description="RepoSec - Cybersecurity scanning tool")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("scan-history", help="Feature 5: scan git history for leaked secrets (coming soon)")
    sub.add_parser("scan-deps", help="Feature 6: check dependencies for known vulnerabilities (coming soon)")

    args = parser.parse_args()
    print(f"Command '{args.command}' is not implemented yet.")

if __name__ == "__main__":
    main()
