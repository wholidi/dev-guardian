from pathlib import Path
from dev_guardian.scanner import scan_repo


def test_scan_repo_detects_env(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=test-key\nOPENAI_BASE_URL=https://example.com/openai/v1/\n")

    result = scan_repo(str(tmp_path))

    assert result["findings"]
    assert result["risks"]