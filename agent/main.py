from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import agent.config as config
from agent.client import APIClient
from agent.reporter import build_report
from agent.runner import run
from agent.validator import validate_and_print


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="backend-testing-agent",
        description="Black-box REST API testing agent for the Mini Social API exam.",
    )
    parser.add_argument("--base-url", default=None, help="API base URL (overrides .env)")
    parser.add_argument("--openapi",  default=None, help="Path to openapi.json")
    parser.add_argument("--schema",   default=None, help="Path to report.schema.json")
    parser.add_argument("--output",   default=None, help="Path for output report.json")
    parser.add_argument("--log",      default=None, help="Path for agent_log.txt")
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    # CLI args override .env / config defaults
    if args.base_url:
        config.BASE_URL    = args.base_url
    if args.openapi:
        config.OPENAPI_PATH = Path(args.openapi)
    if args.schema:
        config.SCHEMA_PATH  = Path(args.schema)
    if args.output:
        config.OUTPUT_PATH  = Path(args.output)
    if args.log:
        config.LOG_PATH     = Path(args.log)

    # Ensure output directory exists
    config.OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*60}")
    print(f"  Backend Testing Agent")
    print(f"  Target : {config.BASE_URL}")
    print(f"  Output : {config.OUTPUT_PATH}")
    print(f"{'='*60}")

    client     = APIClient(base_url=config.BASE_URL, log_path=config.LOG_PATH)
    started_at = datetime.now(timezone.utc)

    try:
        state = run(client, config.BASE_URL)
    finally:
        client.close()

    finished_at = datetime.now(timezone.utc)

    print(f"\n[main] Collected {len(state.findings)} finding(s). Building report...")

    report = build_report(
        base_url=config.BASE_URL,
        findings=state.findings,
        started_at=started_at,
        finished_at=finished_at,
        endpoints_tested=state.endpoints_tested,
    )

    report_dict = json.loads(report.model_dump_json(exclude_none=False))

    # Write report.json
    with open(config.OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(report_dict, f, indent=2, ensure_ascii=False)
    print(f"[main] report.json written → {config.OUTPUT_PATH}")

    # Validate
    print("[main] Validating report against schema...")
    valid = validate_and_print(report_dict, config.SCHEMA_PATH)

    print(f"\n{'='*60}")
    print(f"  Done. {len(state.findings)} findings. Schema valid: {valid}")
    print(f"  Requests made: {client.request_count}")
    print(f"{'='*60}\n")

    sys.exit(0 if valid else 1)


if __name__ == "__main__":
    main()
