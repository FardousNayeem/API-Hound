from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.config import BURST_COUNT
from agent.models.report import Evidence, Finding


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
        id=f"RATE-{str(uuid.uuid4())[:8].upper()}",
        category="rate_limiting",
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
) -> tuple[List[int], APIResponse, float]:
    """
    Fire `count` identical requests and return:
    - list of all status codes
    - last APIResponse (for evidence)
    - min elapsed_ms across the burst
    """
    status_codes: List[int] = []
    last_resp: Optional[APIResponse] = None
    min_elapsed = float("inf")

    for _ in range(count):
        resp = client.request(method, path, token=token, json_body=body)
        status_codes.append(resp.status_code)
        last_resp = resp
        if resp.elapsed_ms < min_elapsed:
            min_elapsed = resp.elapsed_ms
        # Small politeness delay between requests
        time.sleep(0.05)

    return status_codes, last_resp, min_elapsed


# 1: Login brute-force
def _check_login_rate_limit(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path  = "/auth/login"
    body  = {"username": "alice", "password": "WRONG_PASS_PROBE"}

    print(f"    [rate_limiting] Firing {BURST_COUNT} requests at POST /auth/login...")
    codes, last_resp, _ = _burst_test(client, path, "POST", body, BURST_COUNT)
    state.endpoints_tested += 1

    got_429   = 429 in codes
    got_503   = 503 in codes
    all_401   = all(c in (401, 403) for c in codes if c != 0)

    if got_429 or got_503:
        return

    if all_401:
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="high",
            title=f"No rate limiting on POST /auth/login ({BURST_COUNT} requests, no 429)",
            description=(
                f"Fired {BURST_COUNT} consecutive failed login attempts against "
                f"POST /auth/login. All returned HTTP 401 without any throttling, "
                f"delay, lockout, or HTTP 429 response. This endpoint is vulnerable "
                f"to credential stuffing and brute-force attacks."
            ),
            request_info=last_resp.request_info,
            response=last_resp,
            reproduction=(
                f"for i in $(seq 1 {BURST_COUNT}); do\n"
                f"  curl -X POST https://backend-agent-test.onrender.com/auth/login"
                f" -H 'Content-Type: application/json'"
                f" -d '{{\"username\":\"alice\",\"password\":\"WRONG\"}}'\n"
                f"done"
            ),
            expected=f"HTTP 429 Too Many Requests after repeated failures",
            actual=(
                f"All {BURST_COUNT} requests returned 401 with no throttling. "
                f"Status code distribution: {dict(zip(*_count_codes(codes)))}"
            ),
            confidence="high",
            suggested_fix=(
                "Implement rate limiting on /auth/login using IP-based or "
                "username-based throttling (e.g. max 5 failures per minute). "
                "Consider account lockout after N consecutive failures."
            ),
        ))


# 2: Register spam
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
        suffix = f"{int(time.time()*1000) % 100000}_{i}"
        body   = {
            "username": f"rate_probe_{suffix}",
            "password": "rateProbe99!",
            "email":    f"rate_probe_{suffix}@test.local",
        }
        resp = client.post(path, json_body=body)
        codes.append(resp.status_code)
        last_resp = resp
        time.sleep(0.05)
    state.endpoints_tested += 1

    got_429 = 429 in codes
    got_503 = 503 in codes

    if got_429 or got_503:
        return

    success_count = sum(1 for c in codes if c in (200, 201))
    if success_count >= BURST_COUNT // 2:
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="medium",
            title=f"No rate limiting on POST /auth/register ({BURST_COUNT} requests, no 429)",
            description=(
                f"Fired {BURST_COUNT} registration requests against POST /auth/register. "
                f"{success_count} succeeded with no throttling or 429 response. "
                f"Without rate limiting, this endpoint enables account spam, "
                f"resource exhaustion, and enumeration attacks."
            ),
            request_info=last_resp.request_info,
            response=last_resp,
            reproduction=(
                f"for i in $(seq 1 {BURST_COUNT}); do\n"
                f"  curl -X POST https://backend-agent-test.onrender.com/auth/register"
                f" -H 'Content-Type: application/json'"
                f" -d '{{\"username\":\"spam_$i\",\"password\":\"pass\",\"email\":\"spam_$i@x.com\"}}'\n"
                f"done"
            ),
            expected="HTTP 429 Too Many Requests after repeated registration attempts",
            actual=(
                f"{success_count}/{BURST_COUNT} registrations succeeded. "
                f"Status distribution: {_format_codes(codes)}"
            ),
            confidence="high",
            suggested_fix=(
                "Apply IP-based rate limiting to POST /auth/register "
                "(e.g. max 3 registrations per IP per hour)."
            ),
        ))


def _count_codes(codes: List[int]):
    from collections import Counter
    c = Counter(codes)
    return list(c.keys()), list(c.values())


def _format_codes(codes: List[int]) -> str:
    from collections import Counter
    return str(dict(Counter(codes)))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_login_rate_limit(client, state, findings)     # 1
    _check_register_rate_limit(client, state, findings)  # 2

    return findings