from pathlib import Path


def scan_repo(repo_path: str):

    repo = Path(repo_path)

    findings = []

    for file in repo.rglob("*"):

        if file.is_file():
            findings.append(str(file))

    return {
        "files_scanned": len(findings),
        "sample": findings[:5]
    }