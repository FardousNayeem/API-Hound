from __future__ import annotations

import argparse
import json
import sys
import traceback
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import agent.config as config
from agent.client import APIClient
from agent.models.report import (
    BySeverity, Evidence, Finding, Report, Summary, Target,
)
from agent.reporter import build_report
from agent.runner import run
from agent.validator import validate_and_print
from agent.spec import load_openapi

# CLI
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="backend-testing-agent",
        description="Black-box REST API testing agent — Mini Social API exam.",
    )
    parser.add_argument("--base-url", default=None,
                        help=f"API base URL (default: {config.BASE_URL})")
    parser.add_argument("--openapi",  default=None,
                        help=f"Path to openapi.json (default: {config.OPENAPI_PATH})")
    parser.add_argument("--schema",   default=None,
                        help=f"Path to report.schema.json (default: {config.SCHEMA_PATH})")
    parser.add_argument("--output",   default=None,
                        help=f"Output path for report.json (default: {config.OUTPUT_PATH})")
    parser.add_argument("--log",      default=None,
                        help=f"Output path for agent_log.txt (default: {config.LOG_PATH})")
    return parser.parse_args()


# Report serialisation
def _serialise_report(report: Report) -> dict:
    """
    Serialise Report to a plain dict suitable for JSON output.
    - exclude_none=True keeps the report clean and avoids extra keys.
    - by_severity always gets all 4 counts (0 is meaningful, not null).
    """
    raw = json.loads(report.model_dump_json(exclude_none=True))
    by_sev = raw.setdefault("summary", {}).setdefault("by_severity", {})
    for key in ("critical", "high", "medium", "low"):
        by_sev.setdefault(key, 0)
    return raw


def _emergency_finding(reason: str) -> Finding:
    """
    Return a placeholder finding when no real findings were collected.
    The schema requires findings to be non-empty, so this prevents a crash
    and lets the report file still be written for inspection.
    """
    return Finding(
        id="AGENT-ERROR-0001",
        category="endpoint_existence",
        severity="low",
        endpoint="/",
        method="GET",
        title="Agent could not complete testing",
        description=(
            f"The testing agent could not complete its run. Reason: {reason}. "
            "This placeholder ensures the report file is still valid. "
            "Please check agent_log.txt for details."
        ),
        evidence=Evidence(
            request={"method": "GET", "url": config.BASE_URL + "/"},
            response={"status_code": 0, "body": reason},
        ),
        reproduction=f"python -m agent.main --base-url {config.BASE_URL}",
        expected="Agent completes all checks and finds real issues",
        actual=reason,
        confidence="low",
        suggested_fix="Ensure the API is reachable and credentials are correct.",
    )


def main() -> None:
    args = parse_args()

    if args.base_url: config.BASE_URL     = args.base_url
    if args.openapi:  config.OPENAPI_PATH = Path(args.openapi)
    if args.schema:   config.SCHEMA_PATH  = Path(args.schema)
    if args.output:   config.OUTPUT_PATH  = Path(args.output)
    if args.log:      config.LOG_PATH     = Path(args.log)
    
    openapi_spec = load_openapi(config.OPENAPI_PATH)
    config.OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    _banner()

    client     = APIClient(base_url=config.BASE_URL, log_path=config.LOG_PATH)
    started_at = datetime.now(timezone.utc)
    state      = None

    try:
        state = run(client, config.BASE_URL, openapi_spec)
    except Exception:
        print("\n[main] FATAL ERROR during test run:")
        traceback.print_exc()
    finally:
        client.close()

    finished_at = datetime.now(timezone.utc)

    findings = state.findings if state else []
    endpoints_tested = state.endpoints_tested if state else 0

    if not findings:
        reason = (
            "All logins failed — check credentials and API availability"
            if (state and not state.tokens.all_valid())
            else "API unreachable or all checks returned no findings"
        )
        print(f"\n[main] ⚠ No findings collected. Adding placeholder. Reason: {reason}")
        findings = [_emergency_finding(reason)]

    print(f"\n[main] {len(findings)} finding(s). Building report...")

    report = build_report(
        base_url=config.BASE_URL,
        findings=findings,
        started_at=started_at,
        finished_at=finished_at,
        endpoints_tested=endpoints_tested,
        openapi_spec=openapi_spec,
    )

    report_dict = _serialise_report(report)

    with open(config.OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)
    print(f"[main] report.json → {config.OUTPUT_PATH}")

    print("[main] Validating against schema...")
    valid = validate_and_print(report_dict, config.SCHEMA_PATH)

    if state and state.findings:
        _print_findings_summary(state.findings)

    _footer(
        n_findings=len(findings),
        valid=valid,
        n_requests=client.request_count,
        duration=(finished_at - started_at).total_seconds(),
        output=config.OUTPUT_PATH,
        log=config.LOG_PATH,
    )

    sys.exit(0 if valid else 1)


# Display helpers
def _banner() -> None:
    print(f"\n{'='*62}")
    print(f"  Backend Testing Agent  —  {config.AGENT_NAME}")
    print(f"  Target  : {config.BASE_URL}")
    print(f"  Output  : {config.OUTPUT_PATH}")
    print(f"  Log     : {config.LOG_PATH}")
    print(f"{'='*62}")


def _footer(*, n_findings, valid, n_requests, duration, output, log) -> None:
    icon = "✓" if valid else "✗"
    print(f"\n{'='*62}")
    print(f"  {icon} Schema valid : {valid}")
    print(f"  Findings     : {n_findings}")
    print(f"  Requests     : {n_requests}")
    print(f"  Duration     : {duration:.1f}s")
    print(f"  Report       : {output}")
    print(f"  Log          : {log}")
    print(f"{'='*62}\n")


def _print_findings_summary(findings) -> None:
    by_sev = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)

    print(f"\n[main] Findings by severity:")
    for sev in ("critical", "high", "medium", "low"):
        n = by_sev.get(sev, 0)
        if n:
            print(f"  {sev:10s} {n:3d}  {'█' * min(n, 40)}")

    print(f"\n[main] Findings by category:")
    for cat, n in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {cat:28s} {n}")

    print(f"\n[main] All findings:")
    for f in findings:
        print(f"  [{f.severity.upper():8s}] {f.category:25s} {f.method:7s} {f.endpoint}")


if __name__ == "__main__":
    main()