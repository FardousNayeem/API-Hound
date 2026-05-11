from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id, redacted_preview


CATEGORY = "input_validation"


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
    spec_reference: str = "",
) -> Finding:
    return Finding(
        id=stable_finding_id(
            prefix="INPUT",
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
        spec_reference=spec_reference or f"paths.{endpoint}.{method.lower()}",
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _curl(
    client: APIClient,
    method: str,
    path: str,
    body: Optional[Dict[str, Any]] = None,
    token_label: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
) -> str:
    return curl_command(
        client.base_url,
        method,
        path,
        token_label=token_label,
        body=body,
        params=params,
    )


def _is_validation_error(resp: APIResponse) -> bool:
    return 400 <= resp.status_code < 500


def _first_valid_token(state: SessionState) -> tuple[Optional[str], Optional[str]]:
    for label in ("alice", "bob", "carol"):
        token = state.tokens.get(label)
        if token:
            return label, token
    return None, None


def _first_post_id(state: SessionState) -> Optional[int]:
    return (
        next(iter(state.created_post_ids.values()), None)
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )


def _check_comment_body(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _first_valid_token(state)
    post_id = _first_post_id(state)

    if not token or not post_id:
        return

    path = f"/posts/{post_id}/comments"
    generic_path = "/posts/{post_id}/comments"

    cases: List[Tuple[str, Dict[str, Any], str, str]] = [
        (
            "empty body string",
            {"body": ""},
            "Empty comment body accepted",
            "HTTP 422 — body violates minLength: 1 constraint",
        ),
        (
            "body over 500 chars",
            {"body": "x" * 501},
            "Comment body exceeding maxLength=500 accepted",
            "HTTP 422 — body violates maxLength: 500 constraint",
        ),
        (
            "missing body field",
            {},
            "Comment created with missing required 'body' field",
            "HTTP 422 — 'body' is a required field per CommentCreate schema",
        ),
    ]

    for label, body, title_suffix, expected in cases:
        resp = client.post(path, token=token, json_body=body)
        state.endpoints_tested += 1

        if not _is_validation_error(resp):
            title = f"Input not rejected: {title_suffix}"
            findings.append(
                _finding(
                    endpoint=generic_path,
                    method="POST",
                    severity="medium",
                    title=title,
                    description=(
                        f"POST {path} with {label} returned HTTP {resp.status_code}. "
                        f"The OpenAPI spec defines CommentCreate.body with minLength: 1 "
                        f"and maxLength: 500. This input should be rejected."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "POST", path, body, token_label),
                    expected=expected,
                    actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                    spec_reference="components.schemas.CommentCreate.properties.body",
                    suggested_fix=(
                        "Enforce minLength: 1 and maxLength: 500 on CommentCreate.body "
                        "at the request validation layer."
                    ),
                )
            )


def _check_profile_update_types(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _first_valid_token(state)

    if not token:
        return

    path = "/users/me"

    cases: List[Tuple[str, Dict[str, Any], str]] = [
        ("age as string", {"age": "twenty"}, "Age field accepts string value"),
        ("age as negative", {"age": -1}, "Age field accepts negative integer"),
        ("age as float", {"age": 25.5}, "Age field accepts float value"),
    ]

    for label, body, title_suffix in cases:
        resp = client.patch(path, token=token, json_body=body)
        state.endpoints_tested += 1

        if not _is_validation_error(resp):
            title = f"Input not rejected: {title_suffix}"
            findings.append(
                _finding(
                    endpoint="/users/me",
                    method="PATCH",
                    severity="low",
                    title=title,
                    description=(
                        f"PATCH /users/me with {label} ({body}) returned "
                        f"HTTP {resp.status_code}. Age should be a non-negative integer; "
                        f"invalid types and negative values should be rejected."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "PATCH", path, body, token_label),
                    expected="HTTP 422 Unprocessable Entity",
                    actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                    spec_reference="components.schemas.UserPrivate.properties.age",
                    suggested_fix=(
                        "Add a non-negative integer constraint to the age field in "
                        "the update schema and avoid unsafe type coercion."
                    ),
                )
            )


def _check_pagination_params(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/posts"

    cases: List[Tuple[str, Dict[str, Any], str, str]] = [
        (
            "limit=-1",
            {"limit": -1},
            "Negative limit accepted without validation error",
            "HTTP 422 or clamped to 0 — negative limit is nonsensical",
        ),
        (
            "offset=-1",
            {"offset": -1},
            "Negative offset accepted without validation error",
            "HTTP 422 or clamped to 0 — negative offset is nonsensical",
        ),
        (
            "limit=999999",
            {"limit": 999999},
            "Extremely large limit accepted — potential DoS via oversized payload",
            "HTTP 422 or a capped maximum page size",
        ),
    ]

    for label, params, title_suffix, expected in cases:
        resp = client.get(path, params=params)
        state.endpoints_tested += 1

        if label == "limit=999999" and resp.status_code == 200:
            body_len = len(resp.raw_text)
            if body_len > 50_000:
                title = "Uncapped pagination: limit=999999 returns oversized payload"
                findings.append(
                    _finding(
                        endpoint="/posts",
                        method="GET",
                        severity="medium",
                        title=title,
                        description=(
                            f"GET /posts?limit=999999 returned HTTP 200 with a "
                            f"{body_len:,}-byte response body. There is no upper bound "
                            f"enforced on the limit parameter."
                        ),
                        request_info=resp.request_info,
                        response=resp,
                        reproduction=_curl(client, "GET", path, params=params),
                        expected="HTTP 422 or response capped at a maximum page size",
                        actual=f"HTTP 200 with {body_len:,} bytes returned",
                        spec_reference="paths./posts.get.parameters.limit",
                        suggested_fix="Enforce a maximum value, such as le=100, on the limit parameter.",
                    )
                )
            continue

        if not _is_validation_error(resp):
            title = f"Input not rejected: {title_suffix}"
            findings.append(
                _finding(
                    endpoint="/posts",
                    method="GET",
                    severity="low",
                    title=title,
                    description=(
                        f"GET /posts with {label} returned HTTP {resp.status_code}. "
                        f"Invalid pagination values should be rejected."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "GET", path, params=params),
                    expected=expected,
                    actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                    spec_reference="paths./posts.get.parameters",
                    suggested_fix="Add ge=0 constraints to limit and offset parameters.",
                )
            )


def _check_path_param_types(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _first_valid_token(state)

    cases: List[Tuple[str, str, Optional[str], Optional[Dict[str, Any]], Optional[str]]] = [
        ("GET", "/users/not-an-int", None, None, None),
        ("GET", "/posts/not-an-int", None, None, None),
        ("PATCH", "/posts/not-an-int", token, {"body": "test"}, token_label),
        ("DELETE", "/posts/not-an-int", token, None, token_label),
    ]

    generic_map = {
        "/users/not-an-int": "/users/{user_id}",
        "/posts/not-an-int": "/posts/{post_id}",
    }

    for method, path, tok, body, tok_label in cases:
        resp = client.request(method, path, token=tok, json_body=body)
        state.endpoints_tested += 1

        generic_path = generic_map.get(
            path,
            "/posts/{post_id}" if "posts" in path else "/users/{user_id}",
        )

        if resp.status_code not in (404, 422):
            title = f"Non-integer path param not rejected: {method} {path}"
            findings.append(
                _finding(
                    endpoint=generic_path,
                    method=method,
                    severity="low",
                    title=title,
                    description=(
                        f"{method} {path} with a non-integer path parameter returned "
                        f"HTTP {resp.status_code}. Path parameters typed as integer "
                        f"in the spec should be validated before reaching business logic."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, method, path, body, tok_label),
                    expected="HTTP 422 Unprocessable Entity or 404 Not Found",
                    actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                    spec_reference=f"paths.{generic_path}.{method.lower()}.parameters",
                    suggested_fix=(
                        "Declare path parameter types as integer in the router and reject "
                        "non-integer values automatically."
                    ),
                )
            )


def _check_register_fields(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/register"

    cases: List[Tuple[str, Dict[str, Any], str]] = [
        ("missing username", {"password": "pass123"}, "Register accepted with missing username"),
        ("missing password", {"username": "ghost_user"}, "Register accepted with missing password"),
        ("empty username", {"username": "", "password": "pass123"}, "Register accepted with empty username"),
        ("empty password", {"username": "ghost_user2", "password": ""}, "Register accepted with empty password"),
    ]

    for label, body, title_suffix in cases:
        resp = client.post(path, json_body=body)
        state.endpoints_tested += 1

        if not _is_validation_error(resp):
            title = f"Input not rejected: {title_suffix}"
            findings.append(
                _finding(
                    endpoint="/auth/register",
                    method="POST",
                    severity="medium",
                    title=title,
                    description=(
                        f"POST /auth/register with {label} returned HTTP "
                        f"{resp.status_code}. Required registration fields should be "
                        f"validated server-side."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "POST", path, body),
                    expected="HTTP 422 Unprocessable Entity",
                    actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                    spec_reference="paths./auth/register.post.requestBody",
                    suggested_fix=(
                        "Mark username and password as required with minLength: 1 "
                        "in the registration schema."
                    ),
                )
            )


def _check_post_body(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _first_valid_token(state)

    if not token:
        return

    path = "/posts"

    cases: List[Tuple[str, Dict[str, Any], str]] = [
        ("missing body field", {}, "Post created with missing body field"),
        ("empty body string", {"body": ""}, "Post created with empty body string"),
    ]

    for label, body, title_suffix in cases:
        resp = client.post(path, token=token, json_body=body)
        state.endpoints_tested += 1

        if not _is_validation_error(resp):
            title = f"Input not rejected: {title_suffix}"
            findings.append(
                _finding(
                    endpoint="/posts",
                    method="POST",
                    severity="medium",
                    title=title,
                    description=(
                        f"POST /posts with {label} returned HTTP {resp.status_code}. "
                        f"A post with no meaningful content should be rejected."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "POST", path, body, token_label),
                    expected="HTTP 422 Unprocessable Entity",
                    actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                    spec_reference="paths./posts.post.requestBody",
                    suggested_fix="Add minLength: 1 constraint to the post body field in the request schema.",
                )
            )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_comment_body(client, state, findings)
    _check_profile_update_types(client, state, findings)
    _check_pagination_params(client, state, findings)
    _check_path_param_types(client, state, findings)
    _check_register_fields(client, state, findings)
    _check_post_body(client, state, findings)

    return findings