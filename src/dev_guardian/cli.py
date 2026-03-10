import argparse
from dev_guardian.scanner.repo_scanner import scan_repo


def main():
    parser = argparse.ArgumentParser(description="Dev Guardian CLI")

    parser.add_argument(
        "scan",
        nargs="?",
        help="Scan a repository"
    )

    parser.add_argument(
        "--path",
        default=".",
        help="Path to repository"
    )

    args = parser.parse_args()

    results = scan_repo(args.path)

    print(results)


if __name__ == "__main__":
    main()