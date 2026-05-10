from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding


TRACEBACK_SIGNALS = [
    "traceback",
    "Traceback",
    "File \"",
    "line ",
    "Exception",
    "sqlalchemy",
    "sqlite3",
    "psycopg",
    "Internal Server Error",
    "<!DOCTYPE",
    "<html",
    "RuntimeError",
    "KeyError",
    "AttributeError",
    "TypeError",
    "ValueError",
    "NoneType",
    "raise ",
    "assert ",
]


def _has_traceback(raw_text: str) -> List[str]:
    """Return list of matched traceback signals found in raw_text."""
    return [sig for sig in TRACEBACK_SIGNALS if sig in raw_text]


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
        id=f"ERR-{str(uuid.uuid4())[:8].upper()}",
        category="error_handling",
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
        spec_reference=f"paths.{endpoint}.{method.lower()}",
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _curl(method: str, path: str, extra_flags: str = "") -> str:
    return f"curl -X {method} https://backend-agent-test.onrender.com{path}{extra_flags}"


# 1: Malformed JSON body
def _check_malformed_json(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """Send raw invalid JSON strings to POST endpoints."""
    token = state.tokens.alice
    post_id = state.created_post_ids.get("alice") or 1

    endpoints = [
        ("POST", "/auth/login",                     None),
        ("POST", "/posts",                           token),
        ("POST", f"/posts/{post_id}/comments",       token),
    ]

    for method, path, tok in endpoints:
        import httpx
        from agent.config import BASE_URL, TIMEOUT
        headers = {"Content-Type": "application/json"}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"

        try:
            with httpx.Client(timeout=TIMEOUT) as c:
                raw_resp = c.post(
                    BASE_URL + path,
                    content=b"{not valid json!!!",
                    headers=headers,
                )
        except Exception:
            continue

        raw_text = raw_resp.text
        matched = _has_traceback(raw_text)

        if raw_resp.status_code == 500 or matched:
            findings.append(_finding(
                endpoint=path if "{" not in path else path.split("/")[1],
                method=method,
                severity="high" if matched else "medium",
                title=f"Malformed JSON body leaks internals on {method} {path}",
                description=(
                    f"{method} {path} with malformed JSON body returned "
                    f"HTTP {raw_resp.status_code}. "
                    + (f"Traceback signals found: {matched}." if matched else
                       "Server returned 500 without traceback.")
                ),
                request_info={
                    "method": method, "url": BASE_URL + path,
                    "headers": {k: ("[REDACTED]" if k == "Authorization" else v)
                                for k, v in headers.items()},
                    "body": "{not valid json!!!",
                },
                response=APIResponse(
                    status_code=raw_resp.status_code,
                    headers={k.lower(): v for k, v in raw_resp.headers.items()},
                    body=None,
                    raw_text=raw_text[:500],
                    elapsed_ms=0,
                    request_info={},
                ),
                reproduction=_curl(
                    method, path,
                    f" -H 'Content-Type: application/json' -d '{{not valid json!!!'"
                ),
                expected="HTTP 400 or 422 with a clean JSON error message",
                actual=f"HTTP {raw_resp.status_code}: {raw_text[:300]}",
                suggested_fix=(
                    "Wrap JSON parse errors in a global exception handler that "
                    "returns a clean 400/422 response without leaking internals."
                ),
            ))
        state.endpoints_tested += 1


# 2: Wrong Content-Type
def _check_wrong_content_type(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """Send text/plain body to a JSON endpoint."""
    token = state.tokens.alice
    path  = "/posts"
    resp  = client.request(
        "POST", path,
        token=token,
        json_body=None,
        content_type="text/plain",
    )
    state.endpoints_tested += 1

    matched = _has_traceback(resp.raw_text)
    if resp.status_code == 500 or matched:
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="high" if matched else "medium",
            title="Wrong Content-Type causes server error on POST /posts",
            description=(
                f"POST /posts with Content-Type: text/plain returned "
                f"HTTP {resp.status_code}. "
                + (f"Leak signals: {matched}." if matched else "")
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl(
                "POST", path,
                " -H 'Authorization: Bearer <alice_token>'"
                " -H 'Content-Type: text/plain' -d 'plaintext body'"
            ),
            expected="HTTP 415 Unsupported Media Type or 422",
            actual=f"HTTP {resp.status_code}: {resp.raw_text[:300]}",
            suggested_fix="Return 415 for unsupported Content-Type headers.",
        ))


# 3: Oversized payload
def _check_oversized_payload(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """1 MB payload in comment body — server should reject, not crash."""
    token   = state.tokens.alice
    post_id = state.created_post_ids.get("alice") or 1
    path    = f"/posts/{post_id}/comments"

    big_body = {"body": "A" * 1_000_000} 
    resp     = client.post(path, token=token, json_body=big_body)
    state.endpoints_tested += 1

    matched = _has_traceback(resp.raw_text)
    if resp.status_code == 500 or matched:
        findings.append(_finding(
            endpoint="/posts/{post_id}/comments",
            method="POST",
            severity="high",
            title="1 MB comment payload causes server error",
            description=(
                f"POST /posts/{post_id}/comments with a 1 MB body field "
                f"returned HTTP {resp.status_code}. "
                f"The server should reject oversized payloads with 413 or 422."
                + (f" Leak signals: {matched}." if matched else "")
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=(
                f"python3 -c \"import httpx; httpx.post("
                f"'https://backend-agent-test.onrender.com{path}', "
                f"json={{'body': 'A'*1000000}}, "
                f"headers={{'Authorization': 'Bearer <alice_token>'}})\""
            ),
            expected="HTTP 413 Payload Too Large or 422 Unprocessable Entity",
            actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
            suggested_fix=(
                "Set a maximum request body size limit at the server/framework "
                "level and return 413 for oversized requests."
            ),
        ))


# 4: Deeply nested JSON
def _check_deeply_nested_json(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """Send deeply nested JSON — can trigger recursive parser crashes."""
    token = state.tokens.alice
    path  = "/posts"

    nested: Any = {"body": "deep"}
    for _ in range(50):
        nested = {"data": nested}

    resp = client.post(path, token=token, json_body=nested)
    state.endpoints_tested += 1

    matched = _has_traceback(resp.raw_text)
    if resp.status_code == 500 or matched:
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="medium",
            title="Deeply nested JSON body triggers server error on POST /posts",
            description=(
                f"POST /posts with 50-level nested JSON returned "
                f"HTTP {resp.status_code}. "
                "Recursive JSON parsing without depth limits can cause "
                "stack overflows."
                + (f" Leak signals: {matched}." if matched else "")
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl(
                "POST", path,
                " -H 'Authorization: Bearer <alice_token>'"
                " -H 'Content-Type: application/json'"
                " -d '{\"data\":{\"data\":{\"data\":{...50 levels...}}}}'",
            ),
            expected="HTTP 400 or 422 — reject excessively nested input",
            actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
            suggested_fix="Limit JSON parse depth or body size at the middleware layer.",
        ))


# 5: Invalid Authorization header format
def _check_invalid_auth_header(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """Various malformed Authorization header values."""
    path = "/users/me"

    bad_headers = [
        ("Basic dXNlcjpwYXNz",  "Basic auth scheme"),
        ("Token abc123",        "Token scheme"),
        ("Bearer",              "Bearer with no value"),
        ("",                    "empty Authorization value"),
    ]

    for header_val, label in bad_headers:
        import httpx
        from agent.config import BASE_URL, TIMEOUT

        headers = {}
        if header_val:
            headers["Authorization"] = header_val

        try:
            with httpx.Client(timeout=TIMEOUT) as c:
                raw_resp = c.get(BASE_URL + path, headers=headers)
        except Exception:
            continue

        raw_text = raw_resp.text
        matched  = _has_traceback(raw_text)
        state.endpoints_tested += 1

        if raw_resp.status_code == 500 or matched:
            findings.append(_finding(
                endpoint=path,
                method="GET",
                severity="high" if matched else "medium",
                title=f"Malformed auth header ({label}) causes server error",
                description=(
                    f"GET /users/me with Authorization: '{header_val}' "
                    f"returned HTTP {raw_resp.status_code}. "
                    + (f"Internal signals leaked: {matched}." if matched else
                       "Server returned 500 unexpectedly.")
                ),
                request_info={
                    "method": "GET",
                    "url": BASE_URL + path,
                    "headers": headers,
                    "body": None,
                },
                response=APIResponse(
                    status_code=raw_resp.status_code,
                    headers={k.lower(): v for k, v in raw_resp.headers.items()},
                    body=None,
                    raw_text=raw_text[:500],
                    elapsed_ms=0,
                    request_info={},
                ),
                reproduction=_curl("GET", path, f" -H 'Authorization: {header_val}'"),
                expected="HTTP 401 Unauthorized with a clean JSON error",
                actual=f"HTTP {raw_resp.status_code}: {raw_text[:300]}",
                suggested_fix="Parse auth headers defensively; return 401 for all malformed schemes.",
            ))


# 6: Error response shape consistency
def _check_error_shape_consistency(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Compare the error body structure from:
      - 404 (nonexistent resource)
      - 422 (validation error)
      - 401 (unauthenticated)
    They should use a consistent shape, not wildly different schemas.
    """
    responses = {}

    # 404
    r404 = client.get("/posts/999999999")
    state.endpoints_tested += 1
    if r404.status_code == 404:
        responses["404"] = r404.body

    # 422
    r422 = client.post("/auth/login", json_body={})
    state.endpoints_tested += 1
    if r422.status_code == 422:
        responses["422"] = r422.body

    # 401
    r401 = client.get("/users/me")
    state.endpoints_tested += 1
    if r401.status_code in (401, 403):
        responses[str(r401.status_code)] = r401.body

    if len(responses) < 2:
        return

    shapes = {}
    for code, body in responses.items():
        if isinstance(body, dict):
            shapes[code] = set(body.keys())
        elif isinstance(body, str):
            shapes[code] = {"<string>"}
        else:
            shapes[code] = {type(body).__name__}

    shape_values = list(shapes.values())
    if len(shape_values) < 2:
        return

    all_keys = [s for s in shape_values if isinstance(s, set) and s != {"<string>"}]
    if len(all_keys) >= 2:
        intersection = all_keys[0].intersection(*all_keys[1:])
        if not intersection:
            findings.append(_finding(
                endpoint="/posts/{post_id}",
                method="GET",
                severity="low",
                title="Inconsistent error response shapes across 404 / 422 / 401",
                description=(
                    f"Error responses use inconsistent JSON shapes: "
                    + ", ".join(f"HTTP {c}: keys={s}" for c, s in shapes.items())
                    + ". A well-designed API uses a uniform error envelope "
                    "(e.g. {detail: ..., code: ...}) across all error types."
                ),
                request_info=r404.request_info,
                response=r404,
                reproduction="Compare: curl /posts/999999999 vs curl -X POST /auth/login -d '{}'",
                expected="All error responses share a common shape (e.g. {detail: string})",
                actual=f"Shapes differ: {shapes}",
                confidence="medium",
                suggested_fix=(
                    "Use a unified error response model across all error types. "
                    "FastAPI's default {detail: ...} is a good baseline."
                ),
            ))


# 7: Null byte in string fields
def _check_null_byte(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """Null bytes can crash parsers or corrupt databases."""
    token   = state.tokens.alice
    post_id = state.created_post_ids.get("alice") or 1
    path    = f"/posts/{post_id}/comments"

    body = {"body": "hello\x00world"}
    resp = client.post(path, token=token, json_body=body)
    state.endpoints_tested += 1

    matched = _has_traceback(resp.raw_text)
    if resp.status_code == 500 or matched:
        findings.append(_finding(
            endpoint="/posts/{post_id}/comments",
            method="POST",
            severity="medium",
            title="Null byte in comment body causes server error",
            description=(
                f"POST /posts/{post_id}/comments with a null byte (\\x00) in "
                f"the body field returned HTTP {resp.status_code}. "
                "Null bytes in string inputs can corrupt databases or crash parsers."
                + (f" Leak signals: {matched}." if matched else "")
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl(
                "POST", path,
                " -H 'Authorization: Bearer <alice_token>'"
                " -H 'Content-Type: application/json'"
                r" -d '{\"body\": \"hello\u0000world\"}'",
            ),
            expected="HTTP 422 — null bytes should be rejected",
            actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
            suggested_fix="Strip or reject null bytes from all string input fields.",
        ))


# 8: Unicode edge cases
def _check_unicode_edge_cases(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """Unicode edge cases: RTL override, surrogate pairs, emoji."""
    token   = state.tokens.alice
    post_id = state.created_post_ids.get("alice") or 1
    path    = f"/posts/{post_id}/comments"

    unicode_cases = [
        ("RTL override",    "hello \u202e world"),
        ("emoji",           "Hello 🎉🔥💀"),
        ("zero-width",      "invi\u200bsible"), 
        ("surrogate pair",  "test \ud83d\ude00 end"),
    ]

    for label, text in unicode_cases:
        try:
            body = {"body": text}
            resp = client.post(path, token=token, json_body=body)
            state.endpoints_tested += 1
        except Exception:
            continue

        matched = _has_traceback(resp.raw_text)
        if resp.status_code == 500 or matched:
            findings.append(_finding(
                endpoint="/posts/{post_id}/comments",
                method="POST",
                severity="medium",
                title=f"Unicode edge case ({label}) causes server error",
                description=(
                    f"POST /posts/{post_id}/comments with {label} in body "
                    f"returned HTTP {resp.status_code}. "
                    "Unicode edge cases should be handled gracefully."
                    + (f" Leak signals: {matched}." if matched else "")
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(
                    "POST", path,
                    f" -H 'Authorization: Bearer <alice_token>'"
                    f" -H 'Content-Type: application/json'"
                    f" -d '{{\"body\": \"{text[:30]}\"}}'",
                ),
                expected="HTTP 200/201 or 422 — no server crash",
                actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
                confidence="medium",
                suggested_fix="Ensure string fields are properly sanitised for unicode edge cases.",
            ))
            break


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_malformed_json(client, state, findings)           # 1
    _check_wrong_content_type(client, state, findings)       # 2
    _check_oversized_payload(client, state, findings)        # 3
    _check_deeply_nested_json(client, state, findings)       # 4
    _check_invalid_auth_header(client, state, findings)      # 5
    _check_error_shape_consistency(client, state, findings)  # 6
    _check_null_byte(client, state, findings)                # 7
    _check_unicode_edge_cases(client, state, findings)       # 8

    return findings