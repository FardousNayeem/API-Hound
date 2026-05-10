from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

import httpx

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.config import BASE_URL, TIMEOUT
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
        id=f"HTTP-{str(uuid.uuid4())[:8].upper()}",
        category="http_protocol",
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


def _raw_request(
    method: str,
    path: str,
    extra_headers: Optional[Dict[str, str]] = None,
    token: Optional[str] = None,
) -> APIResponse:
    """Send a raw request outside the normal client wrapper."""
    headers: Dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)

    import time
    start = time.perf_counter()
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            resp = c.request(method, BASE_URL + path, headers=headers)
        elapsed_ms = (time.perf_counter() - start) * 1000
        try:
            body = resp.json()
        except Exception:
            body = None
        return APIResponse(
            status_code=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            body=body,
            raw_text=resp.text,
            elapsed_ms=elapsed_ms,
            request_info={
                "method": method,
                "url": BASE_URL + path,
                "headers": {k: ("[REDACTED]" if k.lower() == "authorization" else v)
                            for k, v in headers.items()},
                "body": None,
            },
        )
    except Exception as exc:
        return APIResponse(
            status_code=0,
            headers={},
            body=None,
            raw_text=str(exc),
            elapsed_ms=0,
            request_info={"method": method, "url": BASE_URL + path,
                          "headers": headers, "body": None},
        )


def _curl(method: str, path: str, extra: str = "") -> str:
    return f"curl -X {method} https://backend-agent-test.onrender.com{path}{extra}"


# 1–2: OPTIONS
def _check_options(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    paths = ["/posts", "/users/me", "/auth/login"]

    for path in paths:
        resp = _raw_request("OPTIONS", path)
        state.endpoints_tested += 1

        if resp.status_code == 0:
            continue

        if resp.status_code not in (200, 204):
            findings.append(_finding(
                endpoint=path,
                method="OPTIONS",
                severity="low",
                title=f"OPTIONS {path} returned {resp.status_code}, expected 200/204",
                description=(
                    f"HTTP OPTIONS requests to {path} should return 200 or 204 "
                    f"with an Allow header listing supported methods. "
                    f"Got HTTP {resp.status_code} instead."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl("OPTIONS", path),
                expected="HTTP 200 or 204 with Allow header",
                actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
                suggested_fix="Configure your framework to respond to OPTIONS requests properly.",
            ))
        else:
            allow = resp.headers.get("allow", "")
            if not allow:
                findings.append(_finding(
                    endpoint=path,
                    method="OPTIONS",
                    severity="low",
                    title=f"OPTIONS {path} missing Allow header",
                    description=(
                        f"OPTIONS {path} returned HTTP {resp.status_code} "
                        f"but no Allow header was present. "
                        f"The Allow header should list supported HTTP methods."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl("OPTIONS", path),
                    expected="Allow: GET, POST, OPTIONS (or relevant methods)",
                    actual="Allow header absent",
                    confidence="medium",
                    suggested_fix="Return an Allow header in OPTIONS responses.",
                ))


# 3–4: HEAD
def _check_head(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = (
        state.created_post_ids.get("alice")
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )

    paths = ["/posts", f"/posts/{post_id}"] if post_id else ["/posts"]

    for path in paths:
        resp = _raw_request("HEAD", path)
        state.endpoints_tested += 1

        if resp.status_code == 0:
            continue

        if resp.status_code == 405:
            findings.append(_finding(
                endpoint=path,
                method="HEAD",
                severity="low",
                title=f"HEAD {path} returns 405 Method Not Allowed",
                description=(
                    f"HEAD requests to {path} returned 405. "
                    f"HEAD should be supported on any GET endpoint — "
                    f"it returns the same headers without a response body, "
                    f"useful for caching and content negotiation."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl("HEAD", path),
                expected="HTTP 200 with headers (no body)",
                actual=f"HTTP 405 Method Not Allowed",
                confidence="medium",
                suggested_fix="Most frameworks support HEAD automatically for GET routes; verify it is not explicitly blocked.",
            ))
        elif resp.status_code == 200 and resp.raw_text:
            findings.append(_finding(
                endpoint=path,
                method="HEAD",
                severity="low",
                title=f"HEAD {path} returns a response body (violates RFC 9110)",
                description=(
                    f"HEAD {path} returned HTTP 200 with a non-empty body "
                    f"({len(resp.raw_text)} bytes). Per RFC 9110, HEAD responses "
                    f"must not include a message body."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl("HEAD", path),
                expected="HTTP 200 with empty body",
                actual=f"HTTP 200 with {len(resp.raw_text)}-byte body",
                confidence="high",
                suggested_fix="Ensure the framework strips the body for HEAD responses.",
            ))
        elif resp.status_code not in (200, 204, 404):
            findings.append(_finding(
                endpoint=path,
                method="HEAD",
                severity="low",
                title=f"HEAD {path} returns unexpected status {resp.status_code}",
                description=(
                    f"HEAD {path} returned HTTP {resp.status_code}. "
                    f"Expected 200 (same as GET)."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl("HEAD", path),
                expected="HTTP 200",
                actual=f"HTTP {resp.status_code}",
                confidence="medium",
                suggested_fix="HEAD should mirror GET status codes.",
            ))


# 5–6: Accept header negotiation
def _check_accept_header(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/posts"

    cases = [
        ("text/plain",       "text/plain Accept header"),
        ("application/xml",  "application/xml Accept header"),
        ("application/cbor", "application/cbor Accept header"),
    ]

    for accept_val, label in cases:
        resp = _raw_request("GET", path, extra_headers={"Accept": accept_val})
        state.endpoints_tested += 1

        if resp.status_code == 0:
            continue

        if resp.status_code == 500:
            findings.append(_finding(
                endpoint=path,
                method="GET",
                severity="medium",
                title=f"Unsupported Accept header causes 500: {label}",
                description=(
                    f"GET /posts with Accept: {accept_val} returned HTTP 500. "
                    f"The server should return 406 Not Acceptable or fall back "
                    f"to JSON, not crash."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl("GET", path, f" -H 'Accept: {accept_val}'"),
                expected="HTTP 406 Not Acceptable or HTTP 200 with JSON fallback",
                actual=f"HTTP 500: {resp.raw_text[:200]}",
                suggested_fix="Handle unsupported Accept headers gracefully with 406.",
            ))


# 7–8: Unsupported methods
def _check_unsupported_methods(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    PUT on PATCH-only endpoints, PATCH on GET-only endpoints.
    Should return 405, not 500.
    """
    post_id = state.created_post_ids.get("alice") or 1

    cases = [
        ("PUT",    f"/posts/{post_id}",    "/posts/{post_id}",   None),
        ("PUT",    "/users/me",             "/users/me",          state.tokens.alice),
        ("DELETE", "/posts",                "/posts",             state.tokens.alice),
        ("POST",   f"/posts/{post_id}",    "/posts/{post_id}",   state.tokens.alice),
    ]

    for method, path, generic, token in cases:
        resp = _raw_request(method, path, token=token)
        state.endpoints_tested += 1

        if resp.status_code == 0:
            continue

        if resp.status_code == 500:
            findings.append(_finding(
                endpoint=generic,
                method=method,
                severity="medium",
                title=f"Unsupported method {method} {generic} causes HTTP 500",
                description=(
                    f"{method} {path} is not a documented method for this endpoint "
                    f"but returned HTTP 500 instead of 405 Method Not Allowed."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(method, path),
                expected="HTTP 405 Method Not Allowed",
                actual=f"HTTP 500: {resp.raw_text[:200]}",
                suggested_fix="Return 405 for unsupported HTTP methods with an Allow header.",
            ))
        elif resp.status_code not in (404, 405, 422):
            findings.append(_finding(
                endpoint=generic,
                method=method,
                severity="low",
                title=f"Unsupported method {method} {generic} returns {resp.status_code}",
                description=(
                    f"{method} {path} returned HTTP {resp.status_code}. "
                    f"Undocumented methods should return 405 Method Not Allowed."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(method, path),
                expected="HTTP 405 Method Not Allowed",
                actual=f"HTTP {resp.status_code}",
                confidence="medium",
                suggested_fix="Return 405 with an Allow header for unsupported methods.",
            ))


# 9: Empty body on body-required POST
def _check_empty_body(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """POST with completely empty body (not {}, but literally no bytes)."""
    path  = "/auth/login"
    token = None

    import time
    headers = {"Content-Type": "application/json"}
    start = time.perf_counter()
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            raw_resp = c.post(BASE_URL + path, content=b"", headers=headers)
        elapsed_ms = (time.perf_counter() - start) * 1000
    except Exception:
        return
    state.endpoints_tested += 1

    if raw_resp.status_code == 500:
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="medium",
            title="Empty request body causes HTTP 500 on POST /auth/login",
            description=(
                "POST /auth/login with a completely empty body (0 bytes) "
                "returned HTTP 500. An empty body should return 400 or 422."
            ),
            request_info={"method": "POST", "url": BASE_URL + path,
                          "headers": headers, "body": "(empty)"},
            response=APIResponse(
                status_code=raw_resp.status_code,
                headers={k.lower(): v for k, v in raw_resp.headers.items()},
                body=None,
                raw_text=raw_resp.text[:500],
                elapsed_ms=elapsed_ms,
                request_info={},
            ),
            reproduction=_curl("POST", path, " -H 'Content-Type: application/json' -d ''"),
            expected="HTTP 400 or 422",
            actual=f"HTTP 500: {raw_resp.text[:200]}",
            suggested_fix="Handle empty bodies with a 400 or 422 response.",
        ))


# 10: Trailing slash
def _check_trailing_slash(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """Compare /posts vs /posts/ — should be consistent."""
    resp_no_slash   = client.get("/posts",  params={"limit": 1})
    resp_slash      = client.get("/posts/", params={"limit": 1})
    state.endpoints_tested += 1

    if resp_no_slash.status_code == resp_slash.status_code:
        return

    findings.append(_finding(
        endpoint="/posts",
        method="GET",
        severity="low",
        title="Trailing slash inconsistency: /posts vs /posts/ return different status codes",
        description=(
            f"GET /posts → HTTP {resp_no_slash.status_code}, "
            f"GET /posts/ → HTTP {resp_slash.status_code}. "
            f"Trailing slash handling should be consistent; ideally one "
            f"redirects to the other (301) or both return the same status."
        ),
        request_info=resp_slash.request_info,
        response=resp_slash,
        reproduction="curl https://backend-agent-test.onrender.com/posts/",
        expected=f"Same status as /posts (HTTP {resp_no_slash.status_code})",
        actual=f"HTTP {resp_slash.status_code}",
        confidence="medium",
        suggested_fix="Configure consistent trailing-slash handling (redirect or normalise at router level).",
    ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_options(client, state, findings)             # 1–2
    _check_head(client, state, findings)                # 3–4
    _check_accept_header(client, state, findings)       # 5–6
    _check_unsupported_methods(client, state, findings) # 7–8
    _check_empty_body(client, state, findings)          # 9
    _check_trailing_slash(client, state, findings)      # 10

    return findings