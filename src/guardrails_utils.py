# guardrails_utils.py
# Pydantic v2 schema enforcement for LLM findings output.
# Replaces the original no-op stub. guardrails-ai library NOT required.
#
# What this does:
#   parse(raw_json_str) -> validates each finding, normalises severity,
#   coerces missing fields, and returns a list of FindingModel objects.
#   Caller can do [f.model_dump() for f in validated] to get plain dicts.

from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Allowed severity levels (LLM09 / LLM02 may emit "informational" — normalise)
# ---------------------------------------------------------------------------
_SEV_MAP: Dict[str, str] = {
    "critical":      "critical",
    "crit":          "critical",
    "high":          "high",
    "medium":        "medium",
    "med":           "medium",
    "moderate":      "medium",
    "low":           "low",
    "informational": "low",
    "info":          "low",
    "none":          "low",
}

SeverityLiteral = Literal["low", "medium", "high", "critical"]


class FindingModel(BaseModel):
    """
    Canonical schema for a single security finding produced by ScanAgent
    or enriched by RiskClassifierAgent.
    """
    title:           str = Field(..., min_length=1)
    severity:        SeverityLiteral
    location:        str = Field(default="unknown")
    description:     str = Field(default="")
    recommendation:  str = Field(default="")
    source_file:     Optional[str] = Field(default=None)
    owasp_category:  Optional[str] = Field(default=None)

    @field_validator("severity", mode="before")
    @classmethod
    def normalise_severity(cls, v: Any) -> str:
        """Accept any case / alias → canonical lowercase."""
        key = str(v).strip().lower()
        normalised = _SEV_MAP.get(key)
        if normalised is None:
            # Try prefix match for things like "HIGH - confirmed"
            for k, mapped in _SEV_MAP.items():
                if key.startswith(k):
                    return mapped
            # Fallback: don't reject — demote to low with a warning
            return "low"
        return normalised

    @field_validator("title", "description", "recommendation", "location", mode="before")
    @classmethod
    def coerce_to_str(cls, v: Any) -> str:
        if v is None:
            return ""
        return str(v).strip()

    @model_validator(mode="after")
    def ensure_location_not_empty(self) -> "FindingModel":
        if not self.location:
            self.location = self.source_file or "unknown"
        return self


class FindingsGuard:
    """
    Drop-in replacement for the guardrails-ai Guard interface.
    Usage:
        guard = FindingsGuard()
        validated = guard.parse(raw_json_str)   # -> List[FindingModel]
        dicts = [f.model_dump() for f in validated]
    """

    def parse(self, raw: str) -> List[FindingModel]:
        """
        Parse raw LLM output (JSON string) into validated FindingModel list.
        Raises ValueError on unrecoverable parse failure.
        """
        raw = raw.strip()

        # Strip markdown fences if model wrapped output
        raw = re.sub(r"^```(?:json)?\s*", "", raw, flags=re.IGNORECASE)
        raw = re.sub(r"\s*```$", "", raw)

        # Accept both array and object wrapping {"findings": [...]}
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            # Try to salvage a JSON array substring
            start, end = raw.find("["), raw.rfind("]")
            if start != -1 and end != -1:
                try:
                    data = json.loads(raw[start : end + 1])
                except json.JSONDecodeError:
                    raise ValueError(f"FindingsGuard: unparseable JSON. Original error: {exc}") from exc
            else:
                raise ValueError(f"FindingsGuard: no JSON array found. Original error: {exc}") from exc

        # Unwrap {"findings": [...]} envelope if present
        if isinstance(data, dict):
            data = data.get("findings") or data.get("results") or list(data.values())[0]
        if not isinstance(data, list):
            data = [data]

        validated: List[FindingModel] = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                continue
            try:
                validated.append(FindingModel.model_validate(item))
            except Exception as exc:
                # Log and skip malformed individual findings rather than failing the whole batch
                print(f"[FindingsGuard] Skipping malformed finding #{i}: {exc}")

        return validated


# Module-level singleton — import and call guard_findings(raw_str) directly
_guard = FindingsGuard()


def guard_findings(raw_or_list: Any) -> List[Dict[str, Any]]:
    """
    Convenience function used by multi_agent_workflow.py.

    Accepts either:
      - a raw JSON string (from LLM output)
      - an already-parsed list of dicts (pass-through with schema normalisation)

    Returns a list of plain dicts ready to store / serialise.
    """
    if isinstance(raw_or_list, str):
        validated = _guard.parse(raw_or_list)
    elif isinstance(raw_or_list, list):
        # Already parsed — just validate/normalise each item
        validated = []
        for i, item in enumerate(raw_or_list):
            if isinstance(item, dict):
                try:
                    validated.append(FindingModel.model_validate(item))
                except Exception as exc:
                    print(f"[FindingsGuard] Skipping malformed finding #{i}: {exc}")
    else:
        return []

    return [f.model_dump() for f in validated]
