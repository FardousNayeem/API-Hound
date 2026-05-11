from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.config import BURST_COUNT
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id


CATEGORY = "rate_limiting"


def _finding(
    *,
    endpoint: str,
    method: str,
    severity: str,
    title: str,
    description: str,
    request_info: Dict[str, Any],
    response: APIResponse,
    reproduction: str,
    expected: str,
    actual: str,
    confidence: str = "high",
    suggested_fix: str = "",
) -> Finding:
    return Finding(
        id=stable_finding_id(
            prefix="RATE",
            category=CATEGORY,
            method=method,
            endpoint=endpoint,
            title=title,
        ),
        category=CATEGORY,
        severity=severity,
        endpoint=endpoint,
        method=method,
        title=title,
        description=description,
        evidence=Evidence(
            request=request_info,
            response=response.to_evidence_response(),
        ),
        reproduction=reproduction,
        expected=expected,
        actual=actual,
        spec_reference="",
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _burst_test(
    client: APIClient,
    path: str,
    method: str,
    body: Dict[str, Any],
    count: int,
    token: Optional[str] = None,
) -> tuple[List[int], Optional[APIResponse], float]:
    status_codes: List[int] = []
    last_resp: Optional[APIResponse] = None
    min_elapsed = float("inf")

    for _ in range(count):
        resp = client.request(method, path, token=token, json_body=body)
        status_codes.append(resp.status_code)
        last_resp = resp
        if resp.elapsed_ms < min_elapsed:
            min_elapsed = resp.elapsed_ms
        time.sleep(0.05)

    return status_codes, last_resp, min_elapsed


def _count_codes(codes: List[int]) -> tuple[List[int], List[int]]:
    from collections import Counter

    c = Counter(codes)
    return list(c.keys()), list(c.values())


def _format_codes(codes: List[int]) -> str:
    from collections import Counter

    return str(dict(Counter(codes)))


def _check_login_rate_limit(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/login"
    body = {"username": "alice", "password": "WRONG_PASS_PROBE"}

    print(f"    [rate_limiting] Firing {BURST_COUNT} requests at POST /auth/login...")
    codes, last_resp, _ = _burst_test(client, path, "POST", body, BURST_COUNT)
    state.endpoints_tested += 1

    if not last_resp:
        return

    got_429 = 429 in codes
    got_503 = 503 in codes
    all_auth_failures = all(c in (401, 403) for c in codes if c != 0)

    if got_429 or got_503:
        return

    if all_auth_failures:
        title = f"No rate limiting on POST /auth/login ({BURST_COUNT} requests, no 429)"
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="high",
                title=title,
                description=(
                    f"Fired {BURST_COUNT} consecutive failed login attempts against "
                    f"POST /auth/login. All returned authentication failures without "
                    f"any HTTP 429 throttling response."
                ),
                request_info=last_resp.request_info,
                response=last_resp,
                reproduction=(
                    f"for i in $(seq 1 {BURST_COUNT}); do\n"
                    f"  {curl_command(client.base_url, 'POST', path, body={'username': 'alice', 'password': 'WRONG'})}\n"
                    f"done"
                ),
                expected="HTTP 429 Too Many Requests after repeated failures",
                actual=(
                    f"All {BURST_COUNT} requests returned auth failures with no throttling. "
                    f"Status code distribution: {dict(zip(*_count_codes(codes)))}"
                ),
                confidence="high",
                suggested_fix=(
                    "Implement IP-based and username-based throttling on /auth/login, "
                    "for example max 5 failures per minute with progressive delay."
                ),
            )
        )


def _check_register_rate_limit(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/register"

    print(f"    [rate_limiting] Firing {BURST_COUNT} requests at POST /auth/register...")

    codes: List[int] = []
    last_resp: Optional[APIResponse] = None

    for i in range(BURST_COUNT):
        username = f"rate_probe_{uuid.uuid4().hex[:8]}"
        body = {
            "username": username,
            "password": "ratePass99!",
            "email": f"{username}@probe.test",
        }
        resp = client.post(path, json_body=body)
        codes.append(resp.status_code)
        last_resp = resp
        time.sleep(0.05)

    state.endpoints_tested += 1

    if not last_resp:
        return

    got_429 = 429 in codes
    got_503 = 503 in codes

    if got_429 or got_503:
        return

    success_count = sum(1 for c in codes if c in (200, 201))

    if success_count >= BURST_COUNT // 2:
        title = f"No rate limiting on POST /auth/register ({BURST_COUNT} requests, no 429)"
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="medium",
                title=title,
                description=(
                    f"Fired {BURST_COUNT} registration requests against POST /auth/register. "
                    f"{success_count} succeeded with no throttling or 429 response."
                ),
                request_info=last_resp.request_info,
                response=last_resp,
                reproduction=(
                    f"for i in $(seq 1 {BURST_COUNT}); do\n"
                    f"  {curl_command(client.base_url, 'POST', path, body={'username': 'spam_$i', 'password': 'pass', 'email': 'spam_$i@x.com'})}\n"
                    f"done"
                ),
                expected="HTTP 429 Too Many Requests after repeated registration attempts",
                actual=(
                    f"{success_count}/{BURST_COUNT} registrations succeeded. "
                    f"Status distribution: {_format_codes(codes)}"
                ),
                confidence="high",
                suggested_fix=(
                    "Apply IP-based rate limiting to POST /auth/register, for example "
                    "max 3 registrations per IP per hour."
                ),
            )
        )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_login_rate_limit(client, state, findings)
    _check_register_rate_limit(client, state, findings)

    return findings