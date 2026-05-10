from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import List

from agent.config import AGENT_NAME
from agent.models.report import (
    BySeverity,
    Finding,
    Report,
    Summary,
    Target,
)
from agent.spec import operation_count, spec_version


def build_report(
    base_url: str,
    findings: List[Finding],
    started_at: datetime,
    finished_at: datetime,
    endpoints_tested: int,
    openapi_spec: dict,
) -> Report:
    duration = (finished_at - started_at).total_seconds()

    by_sev = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)

    endpoints_total = operation_count(openapi_spec)
    version = spec_version(openapi_spec)

    if endpoints_total:
        coverage = round((endpoints_tested / endpoints_total) * 100, 1)
        coverage = min(100.0, coverage)
    else:
        coverage = 0.0

    return Report(
        target=Target(
            base_url=base_url,
            tested_at=finished_at.isoformat(),
            spec_version=version,
            agent_name=AGENT_NAME,
            duration_seconds=round(duration, 2),
        ),
        summary=Summary(
            total=len(findings),
            by_severity=BySeverity(
                critical=by_sev.get("critical", 0),
                high=by_sev.get("high", 0),
                medium=by_sev.get("medium", 0),
                low=by_sev.get("low", 0),
            ),
            by_category=dict(by_cat),
            endpoints_tested=endpoints_tested,
            endpoints_total=endpoints_total,
            coverage_percent=coverage,
        ),
        findings=findings,
    )