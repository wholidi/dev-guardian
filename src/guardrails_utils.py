from pydantic import BaseModel
from typing import List, Optional

class Finding(BaseModel):
    title: str
    severity: str
    location: str
    description: str
    recommendation: str
    source_file: str
    owasp_category: Optional[str] = None

FindingsList = List[Finding]

try:
    from guardrails import Guard
    guard_findings = Guard.from_pydantic(
        FindingsList,
        num_reasks=1,
    )
except (ImportError, Exception):
    guard_findings = None
