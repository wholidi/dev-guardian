import re
from pathlib import Path

PATTERNS = {
    "openai": [
        r"from\s+openai\s+import\s+OpenAI",
        r"OPENAI_API_KEY",
        r"api\.openai\.com",
    ],
    "openai_compatible_gateway": [
        r"OPENAI_BASE_URL",
        r"base_url\s*=",
        r"/openai/v1/?",
    ],
    "azure_openai": [
        r"AZURE_OPENAI_API_KEY",
        r"AZURE_OPENAI_ENDPOINT",
        r"azure_endpoint\s*=",
    ],
    "ollama": [
        r"ollama",
        r"localhost:11434",
        r"/api/generate",
    ],
}

SECRET_PATTERNS = [
    r"sk-[A-Za-z0-9\-_]{20,}",
    r"OPENAI_API_KEY\s*=\s*.+",
]

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".tsx", ".json", ".toml", ".yaml", ".yml", ".env", ".md", ".txt"
}


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def scan_repo(repo_path: str) -> dict:
    repo = Path(repo_path)
    findings = []
    risks = []

    for file_path in repo.rglob("*"):
        if not file_path.is_file():
            continue
        if file_path.name.startswith(".git"):
            continue
        if file_path.suffix.lower() not in SCAN_EXTENSIONS and file_path.name != ".env":
            continue

        content = read_text(file_path)
        if not content:
            continue

        for provider, patterns in PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    findings.append({
                        "provider": provider,
                        "file": str(file_path),
                        "evidence": match.group(0),
                    })

        for pattern in SECRET_PATTERNS:
            match = re.search(pattern, content)
            if match:
                risks.append({
                    "type": "possible_secret_exposure",
                    "file": str(file_path),
                    "evidence": match.group(0)[:120],
                })

    return {
        "findings": findings,
        "risks": risks,
    }