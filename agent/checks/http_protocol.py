from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import httpx

from agent.client import APIClient, APIResponse
from agent.config import TIMEOUT
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id, redact


CATEGORY = "http_protocol"


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
            prefix="HTTP",
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
            request=redact(request_info),
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
    client: APIClient,
    method: str,
    path: str,
    extra_headers: Optional[Dict[str, str]] = None,
    token: Optional[str] = None,
) -> APIResponse:
    headers: Dict[str, str] = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if extra_headers:
        headers.update(extra_headers)

    url = client.base_url + path

    start = time.perf_counter()
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            resp = c.request(method, url, headers=headers)
        elapsed_ms = (time.perf_counter() - start) * 1000

        try:
            body = resp.json()
        except Exception:
            body = None

        request_info = {
            "method": method.upper(),
            "url": url,
            "headers": redact(headers),
            "body": None,
        }

        return APIResponse(
            status_code=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            body=body,
            raw_text=resp.text,
            elapsed_ms=elapsed_ms,
            request_info=request_info,
        )
    except Exception as exc:
        return APIResponse(
            status_code=0,
            headers={},
            body=None,
            raw_text=str(exc),
            elapsed_ms=0,
            request_info={
                "method": method.upper(),
                "url": url,
                "headers": redact(headers),
                "body": None,
            },
        )


def _curl(
    client: APIClient,
    method: str,
    path: str,
    extra: str = "",
) -> str:
    return f"{curl_command(client.base_url, method, path)}{extra}"


def _first_post_id(state: SessionState) -> Optional[int]:
    return (
        next(iter(state.created_post_ids.values()), None)
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )


def _first_token(state: SessionState) -> Optional[str]:
    for label in ("alice", "bob", "carol"):
        token = state.tokens.get(label)
        if token:
            return token
    return None


def _check_options(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    paths = ["/posts", "/users/me", "/auth/login"]

    for path in paths:
        resp = _raw_request(client, "OPTIONS", path)
        state.endpoints_tested += 1

        if resp.status_code == 0:
            continue

        if resp.status_code not in (200, 204):
            findings.append(
                _finding(
                    endpoint=path,
                    method="OPTIONS",
                    severity="low",
                    title=f"OPTIONS {path} returned {resp.status_code}, expected 200/204",
                    description=(
                        f"HTTP OPTIONS requests to {path} should return 200 or 204 "
                        f"with an Allow header listing supported methods. Got "
                        f"HTTP {resp.status_code} instead."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "OPTIONS", path),
                    expected="HTTP 200 or 204 with Allow header",
                    actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
                    confidence="medium",
                    suggested_fix="Configure the framework to respond to OPTIONS requests properly.",
                )
            )
        else:
            allow = resp.headers.get("allow", "")
            if not allow:
                findings.append(
                    _finding(
                        endpoint=path,
                        method="OPTIONS",
                        severity="low",
                        title=f"OPTIONS {path} missing Allow header",
                        description=(
                            f"OPTIONS {path} returned HTTP {resp.status_code}, but no "
                            f"Allow header was present."
                        ),
                        request_info=resp.request_info,
                        response=resp,
                        reproduction=_curl(client, "OPTIONS", path),
                        expected="Allow header listing supported HTTP methods",
                        actual="Allow header absent",
                        confidence="medium",
                        suggested_fix="Return an Allow header in OPTIONS responses.",
                    )
                )


def _check_head(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = _first_post_id(state)
    paths = ["/posts", f"/posts/{post_id}"] if post_id is not None else ["/posts"]

    for path in paths:
        resp = _raw_request(client, "HEAD", path)
        state.endpoints_tested += 1

        if resp.status_code == 0:
            continue

        if resp.status_code == 405:
            findings.append(
                _finding(
                    endpoint=path,
                    method="HEAD",
                    severity="low",
                    title=f"HEAD {path} returns 405 Method Not Allowed",
                    description=(
                        f"HEAD requests to {path} returned 405. HEAD should usually "
                        f"be supported on GET endpoints and return the same headers "
                        f"without a response body."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "HEAD", path),
                    expected="HTTP 200 with headers and no body",
                    actual="HTTP 405 Method Not Allowed",
                    confidence="medium",
                    suggested_fix=(
                        "Most frameworks support HEAD automatically for GET routes; "
                        "verify it is not explicitly blocked."
                    ),
                )
            )
        elif resp.status_code == 200 and resp.raw_text:
            findings.append(
                _finding(
                    endpoint=path,
                    method="HEAD",
                    severity="low",
                    title=f"HEAD {path} returns a response body",
                    description=(
                        f"HEAD {path} returned HTTP 200 with a non-empty body "
                        f"({len(resp.raw_text)} bytes). HEAD responses should not "
                        f"include a message body."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "HEAD", path),
                    expected="HTTP 200 with empty body",
                    actual=f"HTTP 200 with {len(resp.raw_text)}-byte body",
                    confidence="high",
                    suggested_fix="Ensure the framework strips the body for HEAD responses.",
                )
            )
        elif resp.status_code not in (200, 204, 404):
            findings.append(
                _finding(
                    endpoint=path,
                    method="HEAD",
                    severity="low",
                    title=f"HEAD {path} returns unexpected status {resp.status_code}",
                    description=(
                        f"HEAD {path} returned HTTP {resp.status_code}. Expected it "
                        f"to mirror the matching GET status code."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "HEAD", path),
                    expected="HTTP 200, 204, or matching GET status",
                    actual=f"HTTP {resp.status_code}",
                    confidence="medium",
                    suggested_fix="HEAD should mirror GET status codes.",
                )
            )


def _check_accept_header(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/posts"

    cases = [
        ("text/plain", "text/plain Accept header"),
        ("application/xml", "application/xml Accept header"),
        ("application/cbor", "application/cbor Accept header"),
    ]

    for accept_val, label in cases:
        resp = _raw_request(client, "GET", path, extra_headers={"Accept": accept_val})
        state.endpoints_tested += 1

        if resp.status_code == 0:
            continue

        if resp.status_code == 500:
            findings.append(
                _finding(
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
                    reproduction=_curl(client, "GET", path, f" -H 'Accept: {accept_val}'"),
                    expected="HTTP 406 Not Acceptable or HTTP 200 with JSON fallback",
                    actual=f"HTTP 500: {resp.raw_text[:200]}",
                    suggested_fix="Handle unsupported Accept headers gracefully with 406.",
                )
            )


def _check_unsupported_methods(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = _first_post_id(state) or 1
    token = _first_token(state)

    cases = [
        ("PUT", f"/posts/{post_id}", "/posts/{post_id}", None),
        ("PUT", "/users/me", "/users/me", token),
        ("DELETE", "/posts", "/posts", token),
        ("POST", f"/posts/{post_id}", "/posts/{post_id}", token),
    ]

    for method, path, generic, tok in cases:
        resp = _raw_request(client, method, path, token=tok)
        state.endpoints_tested += 1

        if resp.status_code == 0:
            continue

        if resp.status_code == 500:
            findings.append(
                _finding(
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
                    reproduction=_curl(client, method, path),
                    expected="HTTP 405 Method Not Allowed",
                    actual=f"HTTP 500: {resp.raw_text[:200]}",
                    suggested_fix="Return 405 for unsupported HTTP methods with an Allow header.",
                )
            )
        elif resp.status_code not in (404, 405, 422):
            findings.append(
                _finding(
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
                    reproduction=_curl(client, method, path),
                    expected="HTTP 405 Method Not Allowed",
                    actual=f"HTTP {resp.status_code}",
                    confidence="medium",
                    suggested_fix="Return 405 with an Allow header for unsupported methods.",
                )
            )


def _check_empty_body(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/login"
    headers = {"Content-Type": "application/json"}

    start = time.perf_counter()
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            raw_resp = c.post(client.base_url + path, content=b"", headers=headers)
        elapsed_ms = (time.perf_counter() - start) * 1000
    except Exception:
        return

    state.endpoints_tested += 1

    if raw_resp.status_code != 500:
        return

    request_info = {
        "method": "POST",
        "url": client.base_url + path,
        "headers": headers,
        "body": "(empty)",
    }

    response = APIResponse(
        status_code=raw_resp.status_code,
        headers={k.lower(): v for k, v in raw_resp.headers.items()},
        body=None,
        raw_text=raw_resp.text[:500],
        elapsed_ms=elapsed_ms,
        request_info=request_info,
    )

    findings.append(
        _finding(
            endpoint=path,
            method="POST",
            severity="medium",
            title="Empty request body causes HTTP 500 on POST /auth/login",
            description=(
                "POST /auth/login with a completely empty body returned HTTP 500. "
                "An empty body should return 400 or 422."
            ),
            request_info=request_info,
            response=response,
            reproduction=_curl(client, "POST", path, " -H 'Content-Type: application/json' -d ''"),
            expected="HTTP 400 or 422",
            actual=f"HTTP 500: {raw_resp.text[:200]}",
            suggested_fix="Handle empty bodies with a 400 or 422 response.",
        )
    )


def _check_trailing_slash(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    resp_no_slash = client.get("/posts", params={"limit": 1})
    resp_slash = client.get("/posts/", params={"limit": 1})
    state.endpoints_tested += 1

    if resp_no_slash.status_code == resp_slash.status_code:
        return

    findings.append(
        _finding(
            endpoint="/posts",
            method="GET",
            severity="low",
            title="Trailing slash inconsistency: /posts vs /posts/ return different status codes",
            description=(
                f"GET /posts returned HTTP {resp_no_slash.status_code}, while "
                f"GET /posts/ returned HTTP {resp_slash.status_code}. Trailing "
                f"slash handling should be consistent."
            ),
            request_info=resp_slash.request_info,
            response=resp_slash,
            reproduction=curl_command(client.base_url, "GET", "/posts/", params={"limit": 1}),
            expected=f"Same status as /posts: HTTP {resp_no_slash.status_code}",
            actual=f"HTTP {resp_slash.status_code}",
            confidence="medium",
            suggested_fix="Configure consistent trailing-slash handling at the router level.",
        )
    )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_options(client, state, findings)
    _check_head(client, state, findings)
    _check_accept_header(client, state, findings)
    _check_unsupported_methods(client, state, findings)
    _check_empty_body(client, state, findings)
    _check_trailing_slash(client, state, findings)

    return findings