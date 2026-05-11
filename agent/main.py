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
from agent.credentials import load_credentials
from agent.models.report import Report
from agent.reporter import build_report
from agent.runner import run
from agent.spec import load_openapi
from agent.validator import validate_and_print


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="backend-testing-agent",
        description="Black-box REST API testing agent — Mini Social API exam.",
    )

    parser.add_argument(
        "--base-url",
        default=None,
        help=f"API base URL (default: {config.BASE_URL})",
    )
    parser.add_argument(
        "--openapi",
        default=None,
        help=f"Path to openapi.json (default: {config.OPENAPI_PATH})",
    )
    parser.add_argument(
        "--credentials",
        default=None,
        help="Path to credentials JSON file",
    )
    parser.add_argument(
        "--schema",
        default=None,
        help=f"Path to report.schema.json (default: {config.SCHEMA_PATH})",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=f"Output path for report.json (default: {config.OUTPUT_PATH})",
    )
    parser.add_argument(
        "--log",
        default=None,
        help=f"Output path for agent_log.txt (default: {config.LOG_PATH})",
    )

    return parser.parse_args()


def _serialise_report(report: Report) -> dict:
    raw = json.loads(report.model_dump_json(exclude_none=True))

    by_sev = raw.setdefault("summary", {}).setdefault("by_severity", {})
    for key in ("critical", "high", "medium", "low"):
        by_sev.setdefault(key, 0)

    return raw


def main() -> None:
    args = parse_args()

    if args.base_url:
        config.BASE_URL = args.base_url
    if args.openapi:
        config.OPENAPI_PATH = Path(args.openapi)
    if args.schema:
        config.SCHEMA_PATH = Path(args.schema)
    if args.output:
        config.OUTPUT_PATH = Path(args.output)
    if args.log:
        config.LOG_PATH = Path(args.log)

    if args.credentials:
        config.CREDENTIALS = load_credentials(Path(args.credentials))

    openapi_spec = load_openapi(config.OPENAPI_PATH)

    config.OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    _print_banner()

    client = APIClient(base_url=config.BASE_URL, log_path=config.LOG_PATH)
    started_at = datetime.now(timezone.utc)
    state = None

    try:
        state = run(client, config.BASE_URL, openapi_spec)
    except Exception:
        print("\n[main] FATAL ERROR during test run:")
        traceback.print_exc()
        sys.exit(1)
    finally:
        client.close()

    finished_at = datetime.now(timezone.utc)

    findings = state.findings if state else []
    endpoints_tested = state.endpoints_tested if state else 0

    if not findings:
        reason = (
            "The test run failed before collecting state."
            if state is None
            else "The agent completed but collected no real findings."
        )
        raise RuntimeError(
            "No real findings collected. Refusing to generate report.json. "
            f"Reason: {reason}"
        )

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

    _print_findings_summary(findings)

    _footer(
        n_findings=len(findings),
        valid=valid,
        n_requests=client.request_count,
        duration=(finished_at - started_at).total_seconds(),
        output=config.OUTPUT_PATH,
        log=config.LOG_PATH,
    )

    sys.exit(0 if valid else 1)


def _print_banner() -> None:
    print(f"\n{'=' * 62}")
    print("  Backend Testing Agent")
    print(f"  Agent   : {config.AGENT_NAME}")
    print(f"  Target  : {config.BASE_URL}")
    print(f"  OpenAPI : {config.OPENAPI_PATH}")
    print(f"  Output  : {config.OUTPUT_PATH}")
    print(f"  Log     : {config.LOG_PATH}")
    print(f"{'=' * 62}")


def _footer(
    *,
    n_findings: int,
    valid: bool,
    n_requests: int,
    duration: float,
    output: Path,
    log: Path,
) -> None:
    icon = "✓" if valid else "✗"

    print(f"\n{'=' * 62}")
    print(f"  {icon} Schema valid : {valid}")
    print(f"  Findings     : {n_findings}")
    print(f"  Requests     : {n_requests}")
    print(f"  Duration     : {duration:.1f}s")
    print(f"  Report       : {output}")
    print(f"  Log          : {log}")
    print(f"{'=' * 62}\n")


def _print_findings_summary(findings) -> None:
    by_sev = Counter(f.severity for f in findings)
    by_cat = Counter(f.category for f in findings)

    print("\n[main] Findings by severity:")
    for sev in ("critical", "high", "medium", "low"):
        n = by_sev.get(sev, 0)
        if n:
            print(f"  {sev:10s} {n:3d}  {'█' * min(n, 40)}")

    print("\n[main] Findings by category:")
    for cat, n in sorted(by_cat.items(), key=lambda x: -x[1]):
        print(f"  {cat:28s} {n}")

    print("\n[main] All findings:")
    for finding in findings:
        print(
            f"  [{finding.severity.upper():8s}] "
            f"{finding.category:25s} "
            f"{finding.method:7s} "
            f"{finding.endpoint}"
        )


if __name__ == "__main__":
    main()