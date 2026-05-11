from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import stable_finding_id, curl_command, redacted_preview, token_label_for_value
from agent.config import CREDENTIALS


CATEGORY = "status_code"


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
            prefix="SC",
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
        spec_reference=spec_reference or f"paths.{endpoint}.{method.lower()}.responses",
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _check_success_codes(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:

    alice_token = state.tokens.alice
    bob_token = state.tokens.bob

    post_id = state.created_post_ids.get("alice")
    bob_id = state.user_ids.get("bob")
    alice_id = state.user_ids.get("alice")

    reg_user = f"status_probe_{uuid.uuid4().hex[:8]}"
    reg_body = {
        "username": reg_user,
        "password": "scProbe99!",
        "email": f"{reg_user}@probe.test",
    }
    
    valid_login_body = None

    for user in ("alice", "bob", "carol"):
        if state.tokens.get(user):
            valid_login_body = {
                "username": CREDENTIALS[user]["username"],
                "password": CREDENTIALS[user]["password"],
            }
            break

    cases: List[Dict[str, Any]] = [
        {
            "method": "POST",
            "path": "/auth/register",
            "expected_code": 201,
            "token": None,
            "body": reg_body,
            "params": None,
            "generic_path": "/auth/register",
        },
        {
            "method": "GET",
            "path": "/posts",
            "expected_code": 200,
            "token": None,
            "body": None,
            "params": {"limit": 5},
            "generic_path": "/posts",
        },
        {
            "method": "GET",
            "path": "/",
            "expected_code": 200,
            "token": None,
            "body": None,
            "params": None,
            "generic_path": "/",
        },
    ]
    
    if valid_login_body:
        cases.append(
            {
                "method": "POST",
                "path": "/auth/login",
                "expected_code": 200,
                "token": None,
                "body": valid_login_body,
                "params": None,
                "generic_path": "/auth/login",
            }
        )

    if alice_token:
        cases.extend(
            [
                {
                    "method": "POST",
                    "path": "/auth/logout",
                    "expected_code": 200,
                    "token": alice_token,
                    "body": None,
                    "params": None,
                    "generic_path": "/auth/logout",
                },
                {
                    "method": "GET",
                    "path": "/users/me",
                    "expected_code": 200,
                    "token": alice_token,
                    "body": None,
                    "params": None,
                    "generic_path": "/users/me",
                },
                {
                    "method": "PATCH",
                    "path": "/users/me",
                    "expected_code": 200,
                    "token": alice_token,
                    "body": {"bio": "status_code probe"},
                    "params": None,
                    "generic_path": "/users/me",
                },
                {
                    "method": "POST",
                    "path": "/posts",
                    "expected_code": 201,
                    "token": alice_token,
                    "body": {"body": "status_code probe post"},
                    "params": None,
                    "generic_path": "/posts",
                },
            ]
        )

    if alice_id is not None:
        cases.append(
            {
                "method": "GET",
                "path": f"/users/{alice_id}",
                "expected_code": 200,
                "token": None,
                "body": None,
                "params": None,
                "generic_path": "/users/{user_id}",
            }
        )

    if post_id is not None:
        cases.extend(
            [
                {
                    "method": "GET",
                    "path": f"/posts/{post_id}",
                    "expected_code": 200,
                    "token": None,
                    "body": None,
                    "params": None,
                    "generic_path": "/posts/{post_id}",
                },
                {
                    "method": "GET",
                    "path": f"/posts/{post_id}/comments",
                    "expected_code": 200,
                    "token": None,
                    "body": None,
                    "params": None,
                    "generic_path": "/posts/{post_id}/comments",
                },
            ]
        )

        if alice_token:
            cases.extend(
                [
                    {
                        "method": "PATCH",
                        "path": f"/posts/{post_id}",
                        "expected_code": 200,
                        "token": alice_token,
                        "body": {"body": "status_code probe edit"},
                        "params": None,
                        "generic_path": "/posts/{post_id}",
                    },
                    {
                        "method": "POST",
                        "path": f"/posts/{post_id}/comments",
                        "expected_code": 201,
                        "token": alice_token,
                        "body": {"body": "status_code probe comment"},
                        "params": None,
                        "generic_path": "/posts/{post_id}/comments",
                    },
                ]
            )

        if bob_token:
            cases.extend(
                [
                    {
                        "method": "POST",
                        "path": f"/posts/{post_id}/like",
                        "expected_code": 200,
                        "token": bob_token,
                        "body": None,
                        "params": None,
                        "generic_path": "/posts/{post_id}/like",
                    },
                    {
                        "method": "DELETE",
                        "path": f"/posts/{post_id}/like",
                        "expected_code": 200,
                        "token": bob_token,
                        "body": None,
                        "params": None,
                        "generic_path": "/posts/{post_id}/like",
                    },
                ]
            )

    if bob_id is not None and alice_token:
        cases.extend(
            [
                {
                    "method": "POST",
                    "path": f"/users/{bob_id}/follow",
                    "expected_code": 200,
                    "token": alice_token,
                    "body": None,
                    "params": None,
                    "generic_path": "/users/{user_id}/follow",
                },
                {
                    "method": "DELETE",
                    "path": f"/users/{bob_id}/follow",
                    "expected_code": 200,
                    "token": alice_token,
                    "body": None,
                    "params": None,
                    "generic_path": "/users/{user_id}/follow",
                },
            ]
        )

    for case in cases:
        method = case["method"]
        path = case["path"]
        expected_code = case["expected_code"]
        token = case["token"]
        body = case["body"]
        params = case["params"]
        generic_path = case["generic_path"]

        resp = client.request(
            method,
            path,
            token=token,
            json_body=body,
            params=params,
        )
        state.endpoints_tested += 1

        if resp.status_code == expected_code:
            continue

        actual_code = resp.status_code
        if actual_code == 0:
            continue

        if actual_code >= 500:
            severity = "high"
            fix = (
                "The server returned a 5xx error for a valid documented request. "
                "Handle the underlying exception and return the documented success "
                "or client-error status code."
            )
        elif expected_code in (200, 201) and actual_code in (401, 403):
            severity = "high"
            fix = (
                "A public request or properly authenticated request is being "
                "incorrectly rejected. Verify authentication and authorization checks."
            )
        elif expected_code == 201 and actual_code == 200:
            severity = "low"
            fix = "Return HTTP 201 Created when a resource is successfully created."
        elif expected_code == 200 and actual_code == 201:
            severity = "low"
            fix = "Return HTTP 200 OK for this operation, not 201 Created."
        else:
            severity = "medium"
            fix = f"Return HTTP {expected_code} for successful {method} {generic_path}."

        token_label = token_label_for_value(state, token)

        title = (
            f"Wrong status code: {method} {generic_path} returned "
            f"{actual_code}, expected {expected_code}"
        )

        findings.append(
            _finding(
                endpoint=generic_path,
                method=method,
                severity=severity,
                title=title,
                description=(
                    f"{method} {path} with valid input returned HTTP {actual_code}. "
                    f"The OpenAPI spec documents HTTP {expected_code} for a "
                    f"successful response."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=curl_command(
                    client.base_url,
                    method,
                    path,
                    token_label=token_label,
                    body=body,
                    params=params,
                ),
                expected=f"HTTP {expected_code}",
                actual=f"HTTP {actual_code}: {redacted_preview(resp.body)}",
                spec_reference=f"paths.{generic_path}.{method.lower()}.responses.{expected_code}",
                suggested_fix=fix,
            )
        )


def _check_wrong_password(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """POST /auth/login with wrong password should return 401 or 403."""
    path = "/auth/login"
    body = {"username": "alice", "password": "definitelyWRONG!"}

    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code in (401, 403):
        return

    severity = "critical" if resp.status_code == 200 else "high"
    title = f"Wrong password login returns HTTP {resp.status_code}, expected 401/403"

    findings.append(
        _finding(
            endpoint=path,
            method="POST",
            severity=severity,
            title=title,
            description=(
                f"POST /auth/login with an incorrect password returned "
                f"HTTP {resp.status_code}. "
                + (
                    "Returning 200 means the login succeeded with a wrong password, "
                    "which is a critical authentication bypass."
                    if resp.status_code == 200
                    else "A non-401/403 response indicates improper credential rejection."
                )
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=curl_command(
                client.base_url,
                "POST",
                path,
                body=body,
            ),
            expected="HTTP 401 Unauthorized or 403 Forbidden",
            actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
            spec_reference="paths./auth/login.post.responses",
            suggested_fix=(
                "Return HTTP 401 with a generic invalid-credentials message when "
                "authentication fails."
            ),
        )
    )


def _check_login_missing_fields(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """POST /auth/login with missing fields should return 400 or 422."""
    path = "/auth/login"
    body = {"username": "alice"}

    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code in (400, 422):
        return

    title = f"Login with missing password returns HTTP {resp.status_code}, expected 422"

    findings.append(
        _finding(
            endpoint=path,
            method="POST",
            severity="medium",
            title=title,
            description=(
                f"POST /auth/login with only username and no password returned "
                f"HTTP {resp.status_code}. Missing required fields should return "
                f"400 Bad Request or 422 Unprocessable Entity."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=curl_command(
                client.base_url,
                "POST",
                path,
                body=body,
            ),
            expected="HTTP 400 Bad Request or 422 Unprocessable Entity",
            actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
            spec_reference="paths./auth/login.post.requestBody",
            suggested_fix=(
                "Validate required fields username and password and return 400/422 "
                "when either field is missing."
            ),
        )
    )


def _check_nonexistent_resources(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """GET nonexistent user and post should return 404."""
    nonexistent = 999999999

    cases = [
        ("GET", f"/users/{nonexistent}", "/users/{user_id}"),
        ("GET", f"/posts/{nonexistent}", "/posts/{post_id}"),
    ]

    for method, path, generic_path in cases:
        resp = client.request(method, path)
        state.endpoints_tested += 1

        if resp.status_code == 404:
            continue

        severity = "high" if resp.status_code >= 500 else "medium"
        title = f"Nonexistent resource returns HTTP {resp.status_code}, expected 404"

        findings.append(
            _finding(
                endpoint=generic_path,
                method=method,
                severity=severity,
                title=title,
                description=(
                    f"{method} {path} references resource ID {nonexistent}, "
                    f"which should not exist, but returned HTTP {resp.status_code} "
                    f"instead of 404."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=curl_command(client.base_url, method, path),
                expected="HTTP 404 Not Found",
                actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                spec_reference=f"paths.{generic_path}.{method.lower()}.responses",
                suggested_fix=(
                    "Return 404 Not Found when the requested resource ID does not exist."
                ),
            )
        )


def _check_duplicate_register(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Registering an existing username should return 400, 409, or 422,
    not 200/201 or 500.
    """
    path = "/auth/register"
    body = {
        "username": "alice",
        "password": "alice123",
        "email": "alice@test.local",
    }

    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code in (400, 409, 422):
        return

    if resp.status_code in (200, 201):
        severity = "critical"
        description = (
            f"Registering with existing username 'alice' returned HTTP "
            f"{resp.status_code}. The server appears to allow duplicate account "
            f"creation, which is a critical data-integrity issue."
        )
    elif resp.status_code >= 500:
        severity = "high"
        description = (
            f"Registering with existing username 'alice' returned HTTP "
            f"{resp.status_code}. The server is not handling duplicate-user "
            f"constraint violations gracefully."
        )
    else:
        severity = "medium"
        description = (
            f"Registering with existing username 'alice' returned HTTP "
            f"{resp.status_code}. Expected a client-error response such as "
            f"400 Bad Request, 409 Conflict, or 422 Unprocessable Entity."
        )

    title = f"Duplicate username registration returns HTTP {resp.status_code}"

    findings.append(
        _finding(
            endpoint=path,
            method="POST",
            severity=severity,
            title=title,
            description=description,
            request_info=resp.request_info,
            response=resp,
            reproduction=curl_command(
                client.base_url,
                "POST",
                path,
                body=body,
            ),
            expected="HTTP 400 Bad Request, 409 Conflict, or 422 Unprocessable Entity",
            actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
            spec_reference="paths./auth/register.post.responses",
            suggested_fix=(
                "Catch duplicate username/email constraint violations and return "
                "HTTP 409 Conflict or another clear client-error response."
            ),
        )
    )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_success_codes(client, state, findings)
    _check_wrong_password(client, state, findings)
    _check_login_missing_fields(client, state, findings)
    _check_nonexistent_resources(client, state, findings)
    _check_duplicate_register(client, state, findings)

    return findings