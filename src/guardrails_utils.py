from pydantic import BaseModel
from typing import List, Optional

# ----- Pydantic schema for validated + repaired findings -----

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
except ImportError:
    guard_findings = None
