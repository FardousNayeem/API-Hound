from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.config import PERF_THRESHOLD_MS
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id


CATEGORY = "performance"


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
            prefix="PERF",
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


def _curl(
    client: APIClient,
    method: str,
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
    token_label: Optional[str] = None,
    body: Optional[Dict[str, Any]] = None,
) -> str:
    return curl_command(
        client.base_url,
        method,
        path,
        token_label=token_label,
        body=body,
        params=params,
    )


def _ms(elapsed: float) -> str:
    return f"{elapsed:.0f}ms"


def _first_valid_token(state: SessionState) -> tuple[Optional[str], Optional[str]]:
    for label in ("alice", "bob", "carol"):
        token = state.tokens.get(label)
        if token:
            return label, token
    return None, None


def _first_user_id(state: SessionState) -> Optional[int]:
    for label in ("alice", "bob", "carol"):
        uid = state.user_ids.get(label)
        if uid is not None:
            return uid
    return next(iter(state.user_ids.values()), None)


def _first_post_id(state: SessionState) -> Optional[int]:
    return (
        next(iter(state.created_post_ids.values()), None)
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )


def _generic_path(path: str) -> str:
    parts = path.strip("/").split("/")
    if len(parts) >= 2 and parts[0] == "posts" and parts[1].isdigit():
        parts[1] = "{post_id}"
    if len(parts) >= 2 and parts[0] == "users" and parts[1].isdigit():
        parts[1] = "{user_id}"
    return "/" + "/".join(parts) if parts != [""] else "/"


def _check_response_times(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _first_valid_token(state)
    post_id = _first_post_id(state)
    user_id = _first_user_id(state)

    endpoints: List[Tuple[str, str, Optional[str], Optional[str], Optional[Dict[str, Any]], Optional[Dict[str, Any]]]] = [
        ("GET", "/posts", None, None, None, {"limit": 20}),
        ("POST", "/auth/login", None, None, {"username": "bob", "password": "bob123"}, None),
    ]

    if token:
        endpoints.append(("GET", "/users/me", token, token_label, None, None))
    if post_id:
        endpoints.append(("GET", f"/posts/{post_id}", None, None, None, None))
        endpoints.append(("GET", f"/posts/{post_id}/comments", None, None, None, None))
    if user_id:
        endpoints.append(("GET", f"/users/{user_id}", None, None, None, None))

    for method, path, tok, tok_label, body, params in endpoints:
        times: List[float] = []
        last_resp: Optional[APIResponse] = None

        for _ in range(2):
            resp = client.request(method, path, token=tok, json_body=body, params=params)
            if resp.status_code != 0:
                times.append(resp.elapsed_ms)
                last_resp = resp
            time.sleep(0.1)

        state.endpoints_tested += 1

        if not times or not last_resp:
            continue

        avg_ms = sum(times) / len(times)

        if avg_ms > PERF_THRESHOLD_MS:
            generic = _generic_path(path)
            severity = "medium" if avg_ms > PERF_THRESHOLD_MS * 1.5 else "low"
            title = f"Slow response: {method} {generic} averaged {_ms(avg_ms)}"

            findings.append(
                _finding(
                    endpoint=generic,
                    method=method,
                    severity=severity,
                    title=title,
                    description=(
                        f"{method} {path} averaged {_ms(avg_ms)} over {len(times)} "
                        f"samples. Threshold: {_ms(PERF_THRESHOLD_MS)}. "
                        f"Individual times: {[_ms(t) for t in times]}."
                    ),
                    request_info=last_resp.request_info,
                    response=last_resp,
                    reproduction=_curl(client, method, path, params=params, token_label=tok_label, body=body),
                    expected=f"Response time < {_ms(PERF_THRESHOLD_MS)}",
                    actual=f"Average: {_ms(avg_ms)} ({[_ms(t) for t in times]})",
                    confidence="medium",
                    suggested_fix=(
                        "Check for missing database indexes, slow queries, N+1 query patterns, "
                        "and consider response caching for read-heavy endpoints."
                    ),
                )
            )


def _check_uncapped_pagination(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/posts"
    params = {"limit": 10000}

    resp = client.get(path, params=params)
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    payload_bytes = len(resp.raw_text.encode("utf-8"))
    elapsed_ms = resp.elapsed_ms
    item_count = len(resp.body) if isinstance(resp.body, list) else 0

    if payload_bytes > 100_000:
        title = f"Uncapped pagination: limit=10000 returns {payload_bytes:,} bytes"
        findings.append(
            _finding(
                endpoint=path,
                method="GET",
                severity="medium",
                title=title,
                description=(
                    f"GET /posts?limit=10000 returned {item_count} items in "
                    f"{payload_bytes:,} bytes ({payload_bytes / 1024:.1f} KB) "
                    f"in {_ms(elapsed_ms)}. There is no server-enforced maximum "
                    f"on the limit parameter."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path, params=params),
                expected="Server caps limit at a reasonable maximum and returns 422 for higher values",
                actual=f"Returned {item_count} items, {payload_bytes:,} bytes in {_ms(elapsed_ms)}",
                confidence="high",
                suggested_fix=(
                    "Add an upper bound to the limit parameter, such as "
                    "limit: int = Query(default=20, ge=1, le=100)."
                ),
            )
        )

    if elapsed_ms > PERF_THRESHOLD_MS and payload_bytes > 10_000:
        title = f"Slow response under large limit: GET /posts?limit=10000 took {_ms(elapsed_ms)}"
        findings.append(
            _finding(
                endpoint=path,
                method="GET",
                severity="medium",
                title=title,
                description=(
                    f"GET /posts?limit=10000 took {_ms(elapsed_ms)} to respond. "
                    f"Large uncapped queries can degrade the server for all users."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path, params=params),
                expected=f"Response time < {_ms(PERF_THRESHOLD_MS)} even for large queries",
                actual=f"{_ms(elapsed_ms)} for {item_count} items",
                confidence="medium",
                suggested_fix="Cap the limit parameter server-side to prevent expensive unbounded queries.",
            )
        )


def _check_cache_headers(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = _first_post_id(state)

    public_endpoints: List[Tuple[str, str, Optional[Dict[str, Any]], str]] = [
        ("GET", "/posts", {"limit": 5}, "/posts"),
    ]

    if post_id:
        public_endpoints.append(("GET", f"/posts/{post_id}", None, "/posts/{post_id}"))

    for method, path, params, generic in public_endpoints:
        resp = client.request(method, path, params=params)
        state.endpoints_tested += 1

        if resp.status_code != 200:
            continue

        has_cache_control = "cache-control" in resp.headers
        has_etag = "etag" in resp.headers
        has_last_modified = "last-modified" in resp.headers

        if not has_cache_control:
            title = f"Missing Cache-Control header on {method} {generic}"
            findings.append(
                _finding(
                    endpoint=generic,
                    method=method,
                    severity="low",
                    title=title,
                    description=(
                        f"{method} {path} does not include a Cache-Control header. "
                        f"Without caching directives, clients and proxies cannot cache responses."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, method, path, params=params),
                    expected="Cache-Control header present",
                    actual="Cache-Control header absent",
                    confidence="medium",
                    suggested_fix=(
                        "Add Cache-Control headers to public read endpoints. "
                        "For frequently changing feeds, use a short max-age."
                    ),
                )
            )

        if not has_etag and not has_last_modified:
            title = f"Missing ETag and Last-Modified on {method} {generic}"
            findings.append(
                _finding(
                    endpoint=generic,
                    method=method,
                    severity="low",
                    title=title,
                    description=(
                        f"{method} {path} provides no ETag or Last-Modified header. "
                        f"These headers enable conditional requests and reduce bandwidth."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, method, path, params=params),
                    expected="ETag or Last-Modified header present",
                    actual="Neither ETag nor Last-Modified present",
                    confidence="low",
                    suggested_fix="Add ETag headers or Last-Modified timestamps to public read endpoints.",
                )
            )


def _check_repeated_get_timing(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/posts"
    params = {"limit": 20}
    times: List[float] = []
    last_resp: Optional[APIResponse] = None

    for _ in range(3):
        resp = client.get(path, params=params)
        if resp.status_code == 200:
            times.append(resp.elapsed_ms)
            last_resp = resp
        time.sleep(0.1)

    state.endpoints_tested += 1

    if len(times) < 3 or not last_resp:
        return

    all_slow = all(t > PERF_THRESHOLD_MS for t in times)
    if all_slow:
        title = f"No response caching observed: GET /posts consistently slow ({[_ms(t) for t in times]})"
        findings.append(
            _finding(
                endpoint=path,
                method="GET",
                severity="low",
                title=title,
                description=(
                    f"GET /posts was called 3 times. Response times: {[_ms(t) for t in times]}. "
                    f"All responses exceeded {_ms(PERF_THRESHOLD_MS)}."
                ),
                request_info=last_resp.request_info,
                response=last_resp,
                reproduction=f"{_curl(client, 'GET', path, params=params)}  # run 3 times",
                expected=f"Repeated identical requests should benefit from caching or stay below {_ms(PERF_THRESHOLD_MS)}",
                actual=f"All 3 requests slow: {[_ms(t) for t in times]}",
                confidence="low",
                suggested_fix="Consider short-TTL caching for the post feed.",
            )
        )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_response_times(client, state, findings)
    _check_uncapped_pagination(client, state, findings)
    _check_cache_headers(client, state, findings)
    _check_repeated_get_timing(client, state, findings)

    return findings