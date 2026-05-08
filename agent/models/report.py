from __future__ import annotations
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


Severity = Literal["critical", "high", "medium", "low"]

Category = Literal[
    "status_code",
    "schema_contract",
    "endpoint_existence",
    "input_validation",
    "authentication",
    "authorization",
    "error_handling",
    "headers_cors",
    "rate_limiting",
    "business_logic",
    "consistency",
    "performance",
    "documentation_drift",
    "http_protocol",
]

Method = Literal["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS", "HEAD"]


# Evidence
class Evidence(BaseModel):
    request: Dict[str, Any]
    response: Dict[str, Any]


# Finding
class Finding(BaseModel):
    id: str = Field(..., min_length=1)
    category: Category
    severity: Severity
    endpoint: str = Field(..., min_length=1)
    method: Method
    title: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    evidence: Evidence
    reproduction: str = Field(..., min_length=1)
    expected: str
    actual: str
    spec_reference: Optional[str] = None
    confidence: Optional[Literal["high", "medium", "low"]] = None
    suggested_fix: Optional[str] = None


# Summary
class BySeverity(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class Summary(BaseModel):
    total: int
    by_severity: BySeverity
    by_category: Optional[Dict[str, int]] = None
    endpoints_tested: Optional[int] = None
    endpoints_total: Optional[int] = None
    coverage_percent: Optional[float] = None


# Target
class Target(BaseModel):
    base_url: str
    tested_at: str
    spec_version: Optional[str] = None
    agent_name: Optional[str] = None
    duration_seconds: Optional[float] = None


# Root Report
class Report(BaseModel):
    target: Target
    summary: Summary
    findings: List[Finding] = Field(..., min_length=1)
