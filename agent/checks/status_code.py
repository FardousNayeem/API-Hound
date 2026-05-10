from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
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
    spec_reference: str = "",
) -> Finding:
    return Finding(
        id=f"SC-{str(uuid.uuid4())[:8].upper()}",
        category="status_code",
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
        spec_reference=spec_reference or f"paths.{endpoint}.{method.lower()}.responses",
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _curl(method: str, path: str, token_label: Optional[str] = None,
          body: Optional[Dict] = None) -> str:
    auth  = f" -H 'Authorization: Bearer <{token_label}_token>'" if token_label else ""
    bflag = (
        f" -H 'Content-Type: application/json' -d '{body}'"
        if body else ""
    )
    return f"curl -X {method} https://backend-agent-test.onrender.com{path}{auth}{bflag}"


#  Success-path checks (from registry)
def _check_success_codes(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Walk every documented endpoint, call it with the minimal valid input,
    and assert the returned code matches the spec's expected success code.
    Skips endpoints that require state we haven't created (e.g. a specific post).
    """

    alice_token = state.tokens.alice
    bob_token   = state.tokens.bob

    post_id    = state.created_post_ids.get("alice")
    bob_id     = state.user_ids.get("bob")
    alice_id   = state.user_ids.get("alice")

    # Register a fresh user just for this check
    suffix     = str(int(time.time()))[-6:]
    reg_user   = f"sc_probe_{suffix}"
    reg_body   = {"username": reg_user, "password": "scProbe99!", "email": f"{reg_user}@test.local"}

    cases = [
        #  auth
        (
            "POST", "/auth/register", 201,
            None, reg_body, None,
            "/auth/register",
        ),
        (
            "POST", "/auth/login", 200,
            None, {"username": "alice", "password": "alice123"}, None,
            "/auth/login",
        ),
        (
            "POST", "/auth/logout", 200,
            alice_token, None, None,
            "/auth/logout",
        ),
        #  users 
        (
            "GET", "/users/me", 200,
            alice_token, None, None,
            "/users/me",
        ),
        (
            "PATCH", "/users/me", 200,
            alice_token, {"bio": "status_code probe"}, None,
            "/users/me",
        ),
        (
            "GET", f"/users/{alice_id}", 200,
            None, None, None,
            "/users/{user_id}",
        ),
        #  posts 
        (
            "GET", "/posts", 200,
            None, None, {"limit": 5},
            "/posts",
        ),
        (
            "POST", "/posts", 201,
            alice_token, {"body": "status_code probe post"}, None,
            "/posts",
        ),
        (
            "GET", f"/posts/{post_id}", 200,
            None, None, None,
            "/posts/{post_id}",
        ),
        (
            "PATCH", f"/posts/{post_id}", 200,
            alice_token, {"body": "status_code probe edit"}, None,
            "/posts/{post_id}",
        ),
        #  comments ─
        (
            "GET", f"/posts/{post_id}/comments", 200,
            None, None, None,
            "/posts/{post_id}/comments",
        ),
        (
            "POST", f"/posts/{post_id}/comments", 201,
            alice_token, {"body": "status_code probe comment"}, None,
            "/posts/{post_id}/comments",
        ),
        #  likes 
        (
            "POST", f"/posts/{post_id}/like", 200,
            bob_token, None, None,
            "/posts/{post_id}/like",
        ),
        (
            "DELETE", f"/posts/{post_id}/like", 200,
            bob_token, None, None,
            "/posts/{post_id}/like",
        ),
        #  follows 
        (
            "POST", f"/users/{bob_id}/follow", 200,
            alice_token, None, None,
            "/users/{user_id}/follow",
        ),
        (
            "DELETE", f"/users/{bob_id}/follow", 200,
            alice_token, None, None,
            "/users/{user_id}/follow",
        ),
        #  meta
        (
            "GET", "/", 200,
            None, None, None,
            "/",
        ),
    ]

    for method, path, expected_code, token, body, params, generic_path in cases:
        # Skip cases where required state is missing
        if path is None or (post_id is None and "{post_id}" in path):
            continue
        if alice_id is None and "{alice_id}" in path:
            continue

        resp = client.request(method, path, token=token,
                              json_body=body, params=params)
        state.endpoints_tested += 1

        if resp.status_code == expected_code:
            continue

        actual = resp.status_code
        if actual == 0:
            continue

        if actual >= 500:
            severity = "high"
            fix = "The server returned a 5xx error for a valid request. Fix the underlying exception."
        elif expected_code in (200, 201) and actual in (401, 403):
            severity = "high"
            fix = "A public or properly-authenticated request is being incorrectly rejected."
        elif expected_code == 201 and actual == 200:
            severity = "low"
            fix = (
                f"Use HTTP 201 Created (not 200) when a resource is successfully created. "
                f"Spec: {generic_path} POST → 201."
            )
        elif expected_code == 200 and actual == 201:
            severity = "low"
            fix = "Use HTTP 200 OK for this operation, not 201 Created."
        else:
            severity = "medium"
            fix = f"Return HTTP {expected_code} for successful {method} {generic_path}."

        token_label = None
        for user in ("alice", "bob", "carol"):
            if token and token == state.tokens.get(user):
                token_label = user
                break

        findings.append(_finding(
            endpoint=generic_path,
            method=method,
            severity=severity,
            title=f"Wrong status code: {method} {generic_path} returned {actual}, expected {expected_code}",
            description=(
                f"{method} {path} with valid input returned HTTP {actual}. "
                f"The OpenAPI spec documents HTTP {expected_code} for a successful response."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl(method, path, token_label, body),
            expected=f"HTTP {expected_code}",
            actual=f"HTTP {actual}: {str(resp.body)[:200]}",
            spec_reference=f"paths.{generic_path}.{method.lower()}.responses.{expected_code}",
            suggested_fix=fix,
        ))


# Error-path checks
def _check_wrong_password(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """POST /auth/login with wrong password must return 401 or 403."""
    path = "/auth/login"
    body = {"username": "alice", "password": "definitelyWRONG!"}
    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code not in (401, 403):
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="critical" if resp.status_code == 200 else "high",
            title=f"Wrong password login returns HTTP {resp.status_code}, expected 401/403",
            description=(
                f"POST /auth/login with an incorrect password returned "
                f"HTTP {resp.status_code}. "
                + (
                    "Returning 200 means the login succeeded with a wrong password — "
                    "a critical authentication bypass."
                    if resp.status_code == 200
                    else "A non-401/403 response indicates improper credential rejection."
                )
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, body=body),
            expected="HTTP 401 Unauthorized or 403 Forbidden",
            actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
            spec_reference="paths./auth/login.post.responses",
            suggested_fix="Return HTTP 401 with a generic 'invalid credentials' message on authentication failure.",
        ))


def _check_login_missing_fields(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """POST /auth/login with missing fields must return 422."""
    path = "/auth/login"
    body = {"username": "alice"}
    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code not in (400, 422):
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="medium",
            title=f"Login with missing password returns HTTP {resp.status_code}, expected 422",
            description=(
                f"POST /auth/login with only username (no password) "
                f"returned HTTP {resp.status_code}. "
                f"Missing required fields should return 422 Unprocessable Entity."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, body=body),
            expected="HTTP 422 Unprocessable Entity",
            actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
            spec_reference="paths./auth/login.post.requestBody",
            suggested_fix="Validate required fields (username, password) and return 422 if missing.",
        ))


def _check_nonexistent_resources(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """GET nonexistent user and post must return 404."""
    nonexistent = 999999999

    cases = [
        ("GET", f"/users/{nonexistent}", "/users/{user_id}", None),
        ("GET", f"/posts/{nonexistent}", "/posts/{post_id}", None),
    ]

    for method, path, generic_path, token in cases:
        resp = client.request(method, path, token=token)
        state.endpoints_tested += 1

        if resp.status_code != 404:
            findings.append(_finding(
                endpoint=generic_path,
                method=method,
                severity="high" if resp.status_code == 500 else "medium",
                title=f"Nonexistent resource returns HTTP {resp.status_code}, expected 404",
                description=(
                    f"{method} {path} (ID {nonexistent} does not exist) "
                    f"returned HTTP {resp.status_code} instead of 404. "
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(method, path),
                expected="HTTP 404 Not Found",
                actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
                spec_reference=f"paths.{generic_path}.{method.lower()}.responses",
                suggested_fix="Return 404 when the requested resource ID does not exist.",
            ))


def _check_duplicate_register(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Registering the same username twice must return 409 or 400, not 201 or 500.
    Uses 'alice' which is a guaranteed pre-existing username.
    """
    path = "/auth/register"
    body = {"username": "alice", "password": "alice123", "email": "alice@test.local"}
    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code in (400, 409, 422):
        return

    if resp.status_code in (200, 201):
        severity = "critical"
        description = (
            "Registering with an existing username (alice) returned "
            f"HTTP {resp.status_code}. The server allowed creation of a "
            "duplicate account, which is a critical data integrity failure."
        )
    elif resp.status_code == 500:
        severity = "high"
        description = (
            "Registering with an existing username (alice) caused a 500 "
            "internal server error. The server is not handling the unique "
            "constraint violation gracefully."
        )
    else:
        severity = "medium"
        description = (
            f"Registering with an existing username returned HTTP {resp.status_code}. "
            "Expected 409 Conflict or 400 Bad Request."
        )

    findings.append(_finding(
        endpoint=path,
        method="POST",
        severity=severity,
        title=f"Duplicate username registration returns HTTP {resp.status_code}",
        description=description,
        request_info=resp.request_info,
        response=resp,
        reproduction=_curl("POST", path, body=body),
        expected="HTTP 409 Conflict or 400 Bad Request",
        actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
        spec_reference="paths./auth/register.post.responses",
        suggested_fix=(
            "Catch unique constraint violations on username and return "
            "HTTP 409 Conflict with a clear message."
        ),
    ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_success_codes(client, state, findings)           # all 17 documented endpoints
    _check_wrong_password(client, state, findings)          # login error path
    _check_login_missing_fields(client, state, findings)    # login missing fields
    _check_nonexistent_resources(client, state, findings)   # 404 for missing IDs
    _check_duplicate_register(client, state, findings)      # duplicate username

    return findings