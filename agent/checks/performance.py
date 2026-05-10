from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.config import PERF_THRESHOLD_MS
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
        id=f"PERF-{str(uuid.uuid4())[:8].upper()}",
        category="performance",
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


def _curl(method: str, path: str, extra: str = "") -> str:
    return f"curl -X {method} https://backend-agent-test.onrender.com{path}{extra}"


def _ms(elapsed: float) -> str:
    return f"{elapsed:.0f}ms"


# 1: Response time across key endpoints
def _check_response_times(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Measure response time for a representative set of endpoints.
    Flag anything over PERF_THRESHOLD_MS (default 2000ms).
    Take 2 samples and use the average to avoid cold-start false positives.
    """
    alice_token = state.tokens.alice
    post_id     = (
        state.created_post_ids.get("alice")
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )
    alice_id    = state.user_ids.get("alice")

    endpoints: List[Tuple[str, str, Optional[str], Optional[Dict], Optional[Dict]]] = [
        ("GET",  "/posts",            None,         None,                        {"limit": 20}),
        ("GET",  "/users/me",         alice_token,  None,                        None),
        ("POST", "/auth/login",       None,         {"username": "alice", "password": "alice123"}, None),
    ]
    if post_id:
        endpoints.append(("GET", f"/posts/{post_id}", None, None, None))
    if alice_id:
        endpoints.append(("GET", f"/users/{alice_id}", None, None, None))
    if post_id:
        endpoints.append(("GET", f"/posts/{post_id}/comments", None, None, None))

    for method, path, token, body, params in endpoints:
        # Take 2 samples, use average
        times: List[float] = []
        last_resp: Optional[APIResponse] = None
        for _ in range(2):
            resp = client.request(method, path, token=token,
                                  json_body=body, params=params)
            if resp.status_code not in (0,):
                times.append(resp.elapsed_ms)
                last_resp = resp
            time.sleep(0.1)

        state.endpoints_tested += 1

        if not times or not last_resp:
            continue

        avg_ms = sum(times) / len(times)

        if avg_ms > PERF_THRESHOLD_MS:
            severity = "medium" if avg_ms > PERF_THRESHOLD_MS * 1.5 else "low"
            generic  = path if not any(c.isdigit() for c in path.split("/")[-1]) else (
                "/posts/{post_id}/comments" if "comments" in path
                else "/posts/{post_id}" if "posts" in path
                else "/users/{user_id}"
            )
            findings.append(_finding(
                endpoint=generic,
                method=method,
                severity=severity,
                title=f"Slow response: {method} {generic} averaged {_ms(avg_ms)}",
                description=(
                    f"{method} {path} averaged {_ms(avg_ms)} over {len(times)} "
                    f"samples (threshold: {_ms(PERF_THRESHOLD_MS)}). "
                    f"Individual times: {[_ms(t) for t in times]}. "
                    f"Slow responses degrade user experience and may indicate "
                    f"missing database indexes or N+1 query issues."
                ),
                request_info=last_resp.request_info,
                response=last_resp,
                reproduction=_curl(method, path),
                expected=f"Response time < {_ms(PERF_THRESHOLD_MS)}",
                actual=f"Average: {_ms(avg_ms)} ({[_ms(t) for t in times]})",
                confidence="medium",
                suggested_fix=(
                    "Check for missing database indexes. "
                    "Use query profiling to identify slow queries. "
                    "Consider adding response caching for read-heavy endpoints."
                ),
            ))


# 2 & 3: Uncapped pagination
def _check_uncapped_pagination(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    GET /posts?limit=10000 — measure payload size and response time.
    Flag if the server returns a huge payload or responds very slowly.
    """
    path   = "/posts"
    params = {"limit": 10000}

    resp = client.get(path, params=params)
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    payload_bytes = len(resp.raw_text.encode("utf-8"))
    elapsed_ms    = resp.elapsed_ms
    item_count    = len(resp.body) if isinstance(resp.body, list) else 0

    if payload_bytes > 100_000:
        findings.append(_finding(
            endpoint=path,
            method="GET",
            severity="medium",
            title=f"Uncapped pagination: limit=10000 returns {payload_bytes:,} bytes",
            description=(
                f"GET /posts?limit=10000 returned {item_count} items in "
                f"{payload_bytes:,} bytes ({payload_bytes/1024:.1f} KB) "
                f"in {_ms(elapsed_ms)}. "
                f"There is no server-enforced maximum on the limit parameter. "
                f"An attacker can exhaust server memory or network bandwidth "
                f"with a single request."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path + "?limit=10000"),
            expected="Server caps limit at a reasonable maximum (e.g. 100) and returns 422 for higher values",
            actual=f"Returned {item_count} items, {payload_bytes:,} bytes in {_ms(elapsed_ms)}",
            confidence="high",
            suggested_fix=(
                "Add an upper bound to the limit parameter: "
                "limit: int = Query(default=20, ge=1, le=100). "
                "Return HTTP 422 if limit exceeds the maximum."
            ),
        ))

    if elapsed_ms > PERF_THRESHOLD_MS and payload_bytes > 10_000:
        findings.append(_finding(
            endpoint=path,
            method="GET",
            severity="medium",
            title=f"Slow response under large limit: GET /posts?limit=10000 took {_ms(elapsed_ms)}",
            description=(
                f"GET /posts?limit=10000 took {_ms(elapsed_ms)} to respond. "
                f"Large uncapped queries can degrade the server for all users "
                f"and are a denial-of-service vector."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path + "?limit=10000"),
            expected=f"Response time < {_ms(PERF_THRESHOLD_MS)} even for large queries",
            actual=f"{_ms(elapsed_ms)} for {item_count} items",
            confidence="medium",
            suggested_fix="Cap the limit parameter server-side to prevent expensive unbounded queries.",
        ))


# 4 & 5: Cache headers
def _check_cache_headers(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Public read endpoints should include Cache-Control and optionally ETag.
    Missing these forces clients to re-fetch identical data on every request.
    """
    public_endpoints = [
        ("GET", "/posts",            {"limit": 5}),
        ("GET", f"/posts/{state.created_post_ids.get('alice') or 1}", None),
    ]

    for method, path, params in public_endpoints:
        resp = client.request(method, path, params=params)
        state.endpoints_tested += 1

        if resp.status_code != 200:
            continue

        has_cache_control = "cache-control" in resp.headers
        has_etag          = "etag" in resp.headers
        has_last_modified = "last-modified" in resp.headers

        if not has_cache_control:
            findings.append(_finding(
                endpoint=path if "{" not in path else "/posts/{post_id}",
                method=method,
                severity="low",
                title=f"Missing Cache-Control header on {method} {path}",
                description=(
                    f"{method} {path} does not include a Cache-Control header. "
                    f"Without caching directives, clients and proxies cannot "
                    f"cache responses, causing unnecessary repeated requests to the server."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(method, path),
                expected="Cache-Control: public, max-age=60 (or similar)",
                actual="Cache-Control header absent",
                confidence="medium",
                suggested_fix=(
                    "Add Cache-Control headers to public read endpoints. "
                    "For frequently-changing feeds use short max-age (30–60s). "
                    "For stable resources use longer max-age with ETag revalidation."
                ),
            ))

        if not has_etag and not has_last_modified:
            findings.append(_finding(
                endpoint=path if "{" not in path else "/posts/{post_id}",
                method=method,
                severity="low",
                title=f"Missing ETag and Last-Modified on {method} {path}",
                description=(
                    f"{method} {path} provides no ETag or Last-Modified header. "
                    f"These headers enable conditional requests (If-None-Match / "
                    f"If-Modified-Since), allowing clients to avoid re-downloading "
                    f"unchanged content."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(method, path),
                expected="ETag or Last-Modified header present",
                actual="Neither ETag nor Last-Modified present",
                confidence="low",
                suggested_fix=(
                    "Add ETag headers (content hash) or Last-Modified (timestamp) "
                    "to enable client-side conditional GET requests."
                ),
            ))


# 6: Repeated identical GET caching
def _check_repeated_get_timing(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Send the same GET /posts request 3 times.
    If response times do not decrease on 2nd/3rd request, there is no caching.
    Only flag if ALL three are slow (avoids false positives on warm cache).
    """
    path   = "/posts"
    params = {"limit": 20}
    times: List[float] = []

    for _ in range(3):
        resp = client.get(path, params=params)
        if resp.status_code == 200:
            times.append(resp.elapsed_ms)
        time.sleep(0.1)
    state.endpoints_tested += 1

    if len(times) < 3:
        return

    all_slow = all(t > PERF_THRESHOLD_MS for t in times)
    if all_slow:
        findings.append(_finding(
            endpoint=path,
            method="GET",
            severity="low",
            title=f"No response caching observed: GET /posts consistently slow ({[_ms(t) for t in times]})",
            description=(
                f"GET /posts was called 3 times. Response times: "
                f"{[_ms(t) for t in times]}. "
                f"All responses exceeded {_ms(PERF_THRESHOLD_MS)}. "
                f"No caching benefit is observed across repeated identical requests."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path + "?limit=20") + "  # run 3 times",
            expected=f"2nd and 3rd requests faster than {_ms(PERF_THRESHOLD_MS)} due to caching",
            actual=f"All 3 requests slow: {[_ms(t) for t in times]}",
            confidence="low",
            suggested_fix=(
                "Consider in-memory caching (Redis, lru_cache) for the post feed. "
                "A short TTL of 5–30 seconds reduces DB load significantly."
            ),
        ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_response_times(client, state, findings)        # 1
    _check_uncapped_pagination(client, state, findings)   # 2 & 3
    _check_cache_headers(client, state, findings)         # 4 & 5
    _check_repeated_get_timing(client, state, findings)   # 6

    return findings