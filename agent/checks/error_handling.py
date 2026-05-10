from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import httpx

from agent.client import APIClient, APIResponse
from agent.config import TIMEOUT
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id, redact


CATEGORY = "error_handling"

TRACEBACK_SIGNALS = [
    "traceback",
    "Traceback",
    'File "',
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
        id=stable_finding_id(
            prefix="ERR",
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
        spec_reference=f"paths.{endpoint}.{method.lower()}",
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _curl(
    client: APIClient,
    method: str,
    path: str,
    extra_flags: str = "",
) -> str:
    return f"{curl_command(client.base_url, method, path)}{extra_flags}"


def _raw_response_to_api_response(
    raw_resp: httpx.Response,
    elapsed_ms: float,
    request_info: Dict[str, Any],
    raw_text_limit: int = 500,
) -> APIResponse:
    try:
        body = raw_resp.json()
    except Exception:
        body = None

    return APIResponse(
        status_code=raw_resp.status_code,
        headers={k.lower(): v for k, v in raw_resp.headers.items()},
        body=body,
        raw_text=raw_resp.text[:raw_text_limit],
        elapsed_ms=elapsed_ms,
        request_info=redact(request_info),
    )


def _token_for_error_tests(state: SessionState) -> tuple[Optional[str], Optional[str]]:
    for label in ("alice", "bob", "carol"):
        token = state.tokens.get(label)
        if token:
            return label, token
    return None, None


def _post_id_for_error_tests(state: SessionState) -> Optional[int]:
    return (
        next(iter(state.created_post_ids.values()), None)
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )


def _check_malformed_json(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _token_for_error_tests(state)
    post_id = _post_id_for_error_tests(state)

    endpoints: List[tuple[str, str, Optional[str], Optional[str]]] = [
        ("POST", "/auth/login", None, None),
    ]

    if token:
        endpoints.append(("POST", "/posts", token, token_label))
        if post_id is not None:
            endpoints.append(("POST", f"/posts/{post_id}/comments", token, token_label))

    for method, path, tok, tok_label in endpoints:
        headers = {"Content-Type": "application/json"}
        if tok:
            headers["Authorization"] = f"Bearer {tok}"

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=TIMEOUT) as c:
                raw_resp = c.post(
                    client.base_url + path,
                    content=b"{not valid json!!!",
                    headers=headers,
                )
            elapsed_ms = (time.perf_counter() - start) * 1000
        except Exception:
            continue

        raw_text = raw_resp.text
        matched = _has_traceback(raw_text)
        state.endpoints_tested += 1

        if raw_resp.status_code == 500 or matched:
            generic_endpoint = (
                "/posts/{post_id}/comments"
                if "/comments" in path
                else path
            )
            request_info = {
                "method": method,
                "url": client.base_url + path,
                "headers": redact(headers),
                "body": "{not valid json!!!",
            }

            title = f"Malformed JSON body leaks internals on {method} {generic_endpoint}"

            findings.append(
                _finding(
                    endpoint=generic_endpoint,
                    method=method,
                    severity="high" if matched else "medium",
                    title=title,
                    description=(
                        f"{method} {path} with malformed JSON body returned "
                        f"HTTP {raw_resp.status_code}. "
                        + (
                            f"Traceback signals found: {matched}."
                            if matched
                            else "Server returned 500 without traceback."
                        )
                    ),
                    request_info=request_info,
                    response=_raw_response_to_api_response(raw_resp, elapsed_ms, request_info),
                    reproduction=(
                        curl_command(
                            client.base_url,
                            method,
                            path,
                            token_label=tok_label,
                            headers={"Content-Type": "application/json"},
                        )
                        + " -d '{not valid json!!!'"
                    ),
                    expected="HTTP 400 or 422 with a clean JSON error message",
                    actual=f"HTTP {raw_resp.status_code}: {raw_text[:300]}",
                    suggested_fix=(
                        "Wrap JSON parse errors in a global exception handler that "
                        "returns a clean 400/422 response without leaking internals."
                    ),
                )
            )


def _check_wrong_content_type(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _token_for_error_tests(state)
    if not token:
        return

    path = "/posts"

    resp = client.request(
        "POST",
        path,
        token=token,
        json_body=None,
        content_type="text/plain",
    )
    state.endpoints_tested += 1

    matched = _has_traceback(resp.raw_text)

    if resp.status_code == 500 or matched:
        findings.append(
            _finding(
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
                reproduction=(
                    curl_command(
                        client.base_url,
                        "POST",
                        path,
                        token_label=token_label,
                        headers={"Content-Type": "text/plain"},
                    )
                    + " -d 'plaintext body'"
                ),
                expected="HTTP 415 Unsupported Media Type or HTTP 422",
                actual=f"HTTP {resp.status_code}: {resp.raw_text[:300]}",
                suggested_fix="Return 415 for unsupported Content-Type headers.",
            )
        )


def _check_oversized_payload(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _token_for_error_tests(state)
    post_id = _post_id_for_error_tests(state)

    if not token or post_id is None:
        return

    path = f"/posts/{post_id}/comments"
    big_body = {"body": "A" * 1_000_000}

    resp = client.post(path, token=token, json_body=big_body)
    state.endpoints_tested += 1

    matched = _has_traceback(resp.raw_text)

    if resp.status_code == 500 or matched:
        findings.append(
            _finding(
                endpoint="/posts/{post_id}/comments",
                method="POST",
                severity="high",
                title="1 MB comment payload causes server error",
                description=(
                    f"POST /posts/{post_id}/comments with a 1 MB body field "
                    f"returned HTTP {resp.status_code}. The server should reject "
                    f"oversized payloads with 413 or 422."
                    + (f" Leak signals: {matched}." if matched else "")
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=(
                    "python -c \"import httpx; "
                    f"httpx.post('{client.base_url}{path}', "
                    "json={'body': 'A'*1000000}, "
                    f"headers={{'Authorization': 'Bearer <{token_label}_token>'}})\""
                ),
                expected="HTTP 413 Payload Too Large or HTTP 422 Unprocessable Entity",
                actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
                suggested_fix=(
                    "Set a maximum request body size limit at the server/framework "
                    "level and return 413 for oversized requests."
                ),
            )
        )


def _check_deeply_nested_json(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _token_for_error_tests(state)
    if not token:
        return

    path = "/posts"

    nested: Any = {"body": "deep"}
    for _ in range(50):
        nested = {"data": nested}

    resp = client.post(path, token=token, json_body=nested)
    state.endpoints_tested += 1

    matched = _has_traceback(resp.raw_text)

    if resp.status_code == 500 or matched:
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="medium",
                title="Deeply nested JSON body triggers server error on POST /posts",
                description=(
                    f"POST /posts with 50-level nested JSON returned "
                    f"HTTP {resp.status_code}. Recursive JSON parsing without depth "
                    f"limits can cause stack overflows."
                    + (f" Leak signals: {matched}." if matched else "")
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=(
                    curl_command(
                        client.base_url,
                        "POST",
                        path,
                        token_label=token_label,
                    )
                    + " -H 'Content-Type: application/json'"
                    + " -d '{\"data\":{\"data\":{\"data\":{...50 levels...}}}}'"
                ),
                expected="HTTP 400 or 422; reject excessively nested input without server crash",
                actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
                suggested_fix="Limit JSON parse depth or body size at the middleware layer.",
            )
        )


def _check_invalid_auth_header(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/users/me"

    bad_headers = [
        ("Basic dXNlcjpwYXNz", "Basic auth scheme"),
        ("Token abc123", "Token scheme"),
        ("Bearer", "Bearer with no value"),
        ("", "empty Authorization value"),
    ]

    for header_val, label in bad_headers:
        headers: Dict[str, str] = {}
        if header_val:
            headers["Authorization"] = header_val

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=TIMEOUT) as c:
                raw_resp = c.get(client.base_url + path, headers=headers)
            elapsed_ms = (time.perf_counter() - start) * 1000
        except Exception:
            continue

        raw_text = raw_resp.text
        matched = _has_traceback(raw_text)
        state.endpoints_tested += 1

        if raw_resp.status_code == 500 or matched:
            request_info = {
                "method": "GET",
                "url": client.base_url + path,
                "headers": redact(headers),
                "body": None,
            }

            title = f"Malformed auth header ({label}) causes server error"

            findings.append(
                _finding(
                    endpoint=path,
                    method="GET",
                    severity="high" if matched else "medium",
                    title=title,
                    description=(
                        f"GET /users/me with Authorization: '{header_val}' returned "
                        f"HTTP {raw_resp.status_code}. "
                        + (
                            f"Internal signals leaked: {matched}."
                            if matched
                            else "Server returned 500 unexpectedly."
                        )
                    ),
                    request_info=request_info,
                    response=_raw_response_to_api_response(raw_resp, elapsed_ms, request_info),
                    reproduction=(
                        curl_command(
                            client.base_url,
                            "GET",
                            path,
                            headers={"Authorization": header_val} if header_val else None,
                        )
                    ),
                    expected="HTTP 401 Unauthorized with a clean JSON error",
                    actual=f"HTTP {raw_resp.status_code}: {raw_text[:300]}",
                    suggested_fix="Parse auth headers defensively; return 401 for all malformed schemes.",
                )
            )


def _check_error_shape_consistency(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    responses: Dict[str, Any] = {}

    r404 = client.get("/posts/999999999")
    state.endpoints_tested += 1
    if r404.status_code == 404:
        responses["404"] = r404.body

    r422 = client.post("/auth/login", json_body={})
    state.endpoints_tested += 1
    if r422.status_code in (400, 422):
        responses[str(r422.status_code)] = r422.body

    r401 = client.get("/users/me")
    state.endpoints_tested += 1
    if r401.status_code in (401, 403):
        responses[str(r401.status_code)] = r401.body

    if len(responses) < 2:
        return

    shapes: Dict[str, set[str]] = {}
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

    all_keys = [s for s in shape_values if s != {"<string>"}]
    if len(all_keys) >= 2:
        intersection = all_keys[0].intersection(*all_keys[1:])
        if not intersection:
            findings.append(
                _finding(
                    endpoint="/posts/{post_id}",
                    method="GET",
                    severity="low",
                    title="Inconsistent error response shapes across 404 / 422 / 401",
                    description=(
                        "Error responses use inconsistent JSON shapes: "
                        + ", ".join(f"HTTP {c}: keys={sorted(s)}" for c, s in shapes.items())
                        + ". A well-designed API uses a uniform error envelope."
                    ),
                    request_info=r404.request_info,
                    response=r404,
                    reproduction=(
                        f"Compare: {curl_command(client.base_url, 'GET', '/posts/999999999')} "
                        f"vs {curl_command(client.base_url, 'POST', '/auth/login', body={})}"
                    ),
                    expected="All error responses share a common shape, such as {'detail': ...}",
                    actual=f"Shapes differ: {shapes}",
                    confidence="medium",
                    suggested_fix="Use a unified error response model across all error types.",
                )
            )


def _check_null_byte(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _token_for_error_tests(state)
    post_id = _post_id_for_error_tests(state)

    if not token or post_id is None:
        return

    path = f"/posts/{post_id}/comments"
    body = {"body": "hello\x00world"}

    resp = client.post(path, token=token, json_body=body)
    state.endpoints_tested += 1

    matched = _has_traceback(resp.raw_text)

    if resp.status_code == 500 or matched:
        findings.append(
            _finding(
                endpoint="/posts/{post_id}/comments",
                method="POST",
                severity="medium",
                title="Null byte in comment body causes server error",
                description=(
                    f"POST /posts/{post_id}/comments with a null byte in the body "
                    f"field returned HTTP {resp.status_code}. Null bytes in string "
                    f"inputs can corrupt databases or crash parsers."
                    + (f" Leak signals: {matched}." if matched else "")
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=curl_command(
                    client.base_url,
                    "POST",
                    path,
                    token_label=token_label,
                    body={"body": "hello\\u0000world"},
                ),
                expected="HTTP 422; null bytes should be rejected cleanly",
                actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
                suggested_fix="Strip or reject null bytes from all string input fields.",
            )
        )


def _check_unicode_edge_cases(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _token_for_error_tests(state)
    post_id = _post_id_for_error_tests(state)

    if not token or post_id is None:
        return

    path = f"/posts/{post_id}/comments"

    unicode_cases = [
        ("RTL override", "hello \u202e world"),
        ("emoji", "Hello 🎉🔥💀"),
        ("zero-width", "invi\u200bsible"),
        ("surrogate pair", "test \ud83d\ude00 end"),
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
            findings.append(
                _finding(
                    endpoint="/posts/{post_id}/comments",
                    method="POST",
                    severity="medium",
                    title=f"Unicode edge case ({label}) causes server error",
                    description=(
                        f"POST /posts/{post_id}/comments with {label} in the body "
                        f"returned HTTP {resp.status_code}. Unicode edge cases "
                        f"should be handled gracefully."
                        + (f" Leak signals: {matched}." if matched else "")
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=curl_command(
                        client.base_url,
                        "POST",
                        path,
                        token_label=token_label,
                        body={"body": text[:30]},
                    ),
                    expected="HTTP 200/201 or 422; no server crash",
                    actual=f"HTTP {resp.status_code}: {resp.raw_text[:200]}",
                    confidence="medium",
                    suggested_fix="Ensure string fields are properly sanitized for Unicode edge cases.",
                )
            )
            break


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_malformed_json(client, state, findings)
    _check_wrong_content_type(client, state, findings)
    _check_oversized_payload(client, state, findings)
    _check_deeply_nested_json(client, state, findings)
    _check_invalid_auth_header(client, state, findings)
    _check_error_shape_consistency(client, state, findings)
    _check_null_byte(client, state, findings)
    _check_unicode_edge_cases(client, state, findings)

    return findings