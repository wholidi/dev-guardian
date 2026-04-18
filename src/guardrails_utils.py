try:
    from guardrails import Guard
    # your existing guard_findings setup here
except ImportError:
    Guard = None
    guard_findings = None
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

guard_findings = Guard.from_pydantic(
    FindingsList,
    # e.g. auto-correct invalid severities:
    num_reasks=1,
)
