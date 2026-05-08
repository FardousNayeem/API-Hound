from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import List

from agent.config import AGENT_NAME, SPEC_VERSION, TOTAL_ENDPOINTS
from agent.models.report import (
    BySeverity, Finding, Report, Summary, Target,
)


def build_report(
    base_url: str,
    findings: List[Finding],
    started_at: datetime,
    finished_at: datetime,
    endpoints_tested: int,
) -> Report:
    duration = (finished_at - started_at).total_seconds()

    by_sev = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)

    coverage = round((endpoints_tested / TOTAL_ENDPOINTS) * 100, 1) if TOTAL_ENDPOINTS else 0.0

    return Report(
        target=Target(
            base_url=base_url,
            tested_at=started_at.isoformat(),
            spec_version=SPEC_VERSION,
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
            endpoints_total=TOTAL_ENDPOINTS,
            coverage_percent=coverage,
        ),
        findings=findings,
    )
