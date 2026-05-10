from __future__ import annotations

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
        id=f"DRIFT-{str(uuid.uuid4())[:8].upper()}",
        category="documentation_drift",
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
        spec_reference=spec_reference,
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _curl(method: str, path: str, token_label: Optional[str] = None,
          body: Optional[Dict] = None) -> str:
    auth  = f" -H 'Authorization: Bearer <{token_label}_token>'" if token_label else ""
    bflag = (f" -H 'Content-Type: application/json' -d '{body}'"
             if body else "")
    return f"curl -X {method} https://backend-agent-test.onrender.com{path}{auth}{bflag}"


# 1: auth header required:false on protected routes
def _check_auth_required_false_drift(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    The spec marks the Authorization header as required:false on protected
    endpoints (GET /users/me, POST /posts, etc). This is likely a spec error.
    Verify: does calling without auth return 401/403 (reality) or 200 (as spec implies)?
    """
    path = "/users/me"
    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code in (401, 403):
        findings.append(_finding(
            endpoint=path,
            method="GET",
            severity="medium",
            title="Spec drift: Authorization header marked required:false but endpoint enforces auth",
            description=(
                f"The OpenAPI spec marks the Authorization header as "
                f"'required: false' on GET /users/me (and other protected endpoints). "
                f"However, calling the endpoint without a token returns "
                f"HTTP {resp.status_code}, proving auth IS required. "
                f"The spec does not accurately document the authentication requirement."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected="Spec should declare Authorization as required:true or use a security scheme",
            actual=f"Spec says required:false, but API returns HTTP {resp.status_code} without auth",
            spec_reference="paths./users/me.get.parameters.authorization.required",
            confidence="high",
            suggested_fix=(
                "Use OpenAPI security schemes (BearerAuth) instead of manually "
                "declaring the Authorization header as a parameter. "
                "Mark the security scheme as required on protected operations."
            ),
        ))
    elif resp.status_code == 200:
        findings.append(_finding(
            endpoint=path,
            method="GET",
            severity="low",
            title="Spec drift: Authorization marked required:false and API does not enforce auth",
            description=(
                f"GET /users/me with no Authorization header returned HTTP 200. "
                f"The spec marks Authorization as required:false, which matches "
                f"observed behaviour — but both the spec and the implementation "
                f"are incorrect. Protected endpoints should require auth."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected="HTTP 401 — auth should be required",
            actual="HTTP 200 — endpoint accessible without auth",
            spec_reference="paths./users/me.get.parameters.authorization.required",
            confidence="high",
            suggested_fix=(
                "Mark Authorization as required in the spec AND enforce it in the API."
            ),
        ))


# 2–4: Status code drift on creation endpoints
def _check_creation_status_codes(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Spec says 201 for register, create post, create comment.
    If the API returns 200 instead, that's documentation drift.
    """
    import time
    alice_token = state.tokens.alice
    post_id     = state.created_post_ids.get("alice") or 1

    cases = [
        (
            "POST", "/auth/register", None,
            {
                "username": f"drift_{str(int(time.time()))[-5:]}",
                "password": "driftpass99",
                "email":    f"drift_{str(int(time.time()))[-5:]}@test.local",
            },
            201,
            "paths./auth/register.post.responses.201",
        ),
        (
            "POST", "/posts", alice_token,
            {"body": "documentation drift test post"},
            201,
            "paths./posts.post.responses.201",
        ),
        (
            "POST", f"/posts/{post_id}/comments", alice_token,
            {"body": "documentation drift test comment"},
            201,
            "paths./posts/{post_id}/comments.post.responses.201",
        ),
    ]

    generic_map = {
        "/auth/register":          "/auth/register",
        "/posts":                  "/posts",
        f"/posts/{post_id}/comments": "/posts/{post_id}/comments",
    }

    for method, path, token, body, expected_code, spec_ref in cases:
        resp = client.request(method, path, token=token, json_body=body)
        state.endpoints_tested += 1

        if resp.status_code == expected_code:
            continue

        if resp.status_code in (200, 201):
            generic = generic_map.get(path, path)
            findings.append(_finding(
                endpoint=generic,
                method=method,
                severity="low",
                title=(
                    f"Spec drift: {method} {generic} spec says {expected_code}, "
                    f"API returns {resp.status_code}"
                ),
                description=(
                    f"The OpenAPI spec documents HTTP {expected_code} for "
                    f"a successful {method} {generic}. "
                    f"The API returned HTTP {resp.status_code}. "
                    f"This is documentation drift — the spec and implementation disagree "
                    f"on the success status code."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(method, path,
                                   "alice" if token else None, body),
                expected=f"HTTP {expected_code} as documented in spec",
                actual=f"HTTP {resp.status_code}",
                spec_reference=spec_ref,
                confidence="high",
                suggested_fix=(
                    f"Either update the spec to document {resp.status_code}, "
                    f"or update the API to return {expected_code} for resource creation."
                ),
            ))


# 5: undocumented requestBody check
def _check_login_request_body_undocumented(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    The OpenAPI spec for POST /auth/login has no requestBody defined.
    But the API clearly requires username and password.
    This is documentation drift — the spec omits a required input.
    """
    path = "/auth/login"
    resp = client.post(path, json_body={})
    state.endpoints_tested += 1

    if resp.status_code in (400, 422):
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="medium",
            title="Spec drift: POST /auth/login has no requestBody in spec but API requires one",
            description=(
                "The OpenAPI spec for POST /auth/login does not define a requestBody "
                "schema. However, the API requires username and password fields and "
                f"returns HTTP {resp.status_code} when they are missing. "
                "Clients relying on the spec alone would not know what to send."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, body={}),
            expected="Spec should define requestBody with username and password fields",
            actual="No requestBody in spec; API returns 422 for missing fields",
            spec_reference="paths./auth/login.post.requestBody",
            confidence="high",
            suggested_fix=(
                "Add a requestBody schema to POST /auth/login in the OpenAPI spec "
                "with username (string, required) and password (string, required)."
            ),
        ))


# 6: POST /auth/logout
def _check_logout_underdocumented(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    POST /auth/logout has no documented requestBody, no security requirement,
    and an empty response schema {}. Verify actual behaviour.
    """
    alice_token = state.tokens.alice
    if not alice_token:
        return

    path = "/auth/logout"
    resp = client.post(path, token=alice_token)
    state.endpoints_tested += 1

    if resp.status_code == 200 and isinstance(resp.body, dict) and resp.body:
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="low",
            title="Spec drift: POST /auth/logout returns fields but spec documents empty response {}",
            description=(
                f"POST /auth/logout returned HTTP 200 with body {resp.body}. "
                f"The spec defines the response schema as empty {{}}. "
                f"The actual response contains undocumented fields."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, "alice"),
            expected="Empty JSON body {} as per spec",
            actual=f"Body contains: {list(resp.body.keys())}",
            spec_reference="paths./auth/logout.post.responses.200",
            confidence="medium",
            suggested_fix=(
                "Update the spec to document the actual response schema "
                "returned by POST /auth/logout."
            ),
        ))


# 7: Undocumented extra fields in responses
def _check_undocumented_response_fields(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Check if responses contain fields not defined in the OpenAPI schemas.
    Extra fields may indicate accidental data exposure.
    """
    alice_token = state.tokens.alice
    alice_id    = state.user_ids.get("alice")
    if not alice_token or not alice_id:
        return

    resp = client.get(f"/users/{alice_id}")
    state.endpoints_tested += 1

    if resp.status_code == 200 and isinstance(resp.body, dict):
        documented_public = {"id", "username", "bio"}
        extra = set(resp.body.keys()) - documented_public

        if extra:
            findings.append(_finding(
                endpoint="/users/{user_id}",
                method="GET",
                severity="medium",
                title=f"Spec drift: GET /users/{{id}} returns undocumented fields: {sorted(extra)}",
                description=(
                    f"GET /users/{alice_id} returned fields {sorted(extra)} "
                    f"that are not defined in the UserPublic schema. "
                    f"The spec only documents: id, username, bio. "
                    f"Extra fields may expose sensitive data unintentionally."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl("GET", f"/users/{alice_id}"),
                expected="Response contains only: id, username, bio",
                actual=f"Extra undocumented fields: {sorted(extra)}",
                spec_reference="components.schemas.UserPublic",
                confidence="high",
                suggested_fix=(
                    "Use an explicit response_model=UserPublic in the route "
                    "decorator to strip undocumented fields."
                ),
            ))

    post_id = state.created_post_ids.get("alice")
    if post_id:
        comment_resp = client.get(f"/posts/{post_id}/comments")
        state.endpoints_tested += 1
        if (comment_resp.status_code == 200
                and isinstance(comment_resp.body, list)
                and comment_resp.body
                and isinstance(comment_resp.body[0], dict)):
            documented_comment = {"id", "post_id", "author_id", "body"}
            extra_c = set(comment_resp.body[0].keys()) - documented_comment
            if extra_c:
                findings.append(_finding(
                    endpoint="/posts/{post_id}/comments",
                    method="GET",
                    severity="low",
                    title=f"Spec drift: comment response contains undocumented fields: {sorted(extra_c)}",
                    description=(
                        f"CommentResponse objects contain fields {sorted(extra_c)} "
                        f"not defined in the spec schema. "
                        f"Documented fields: id, post_id, author_id, body."
                    ),
                    request_info=comment_resp.request_info,
                    response=comment_resp,
                    reproduction=_curl("GET", f"/posts/{post_id}/comments"),
                    expected="CommentResponse contains only: id, post_id, author_id, body",
                    actual=f"Extra fields: {sorted(extra_c)}",
                    spec_reference="components.schemas.CommentResponse",
                    confidence="high",
                    suggested_fix="Use response_model=CommentResponse to strip undocumented fields.",
                ))


# 8: token_type casing
def _check_token_type_casing(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Spec default: token_type = "bearer" (lowercase).
    Some implementations return "Bearer" (capitalised) — drift.
    """
    path = "/auth/login"
    body = {"username": "alice", "password": "alice123"}
    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code != 200 or not isinstance(resp.body, dict):
        return

    token_type = resp.body.get("token_type")
    if token_type and token_type != "bearer":
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="low",
            title=f"Spec drift: token_type is '{token_type}', spec default is 'bearer'",
            description=(
                f"POST /auth/login returned token_type: '{token_type}'. "
                f"The OpenAPI spec defines the default as 'bearer' (lowercase). "
                f"While RFC 6750 is case-insensitive for the scheme, "
                f"the spec and implementation should agree."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, body=body),
            expected="token_type: 'bearer' (as per spec default)",
            actual=f"token_type: '{token_type}'",
            spec_reference="components.schemas.TokenResponse.properties.token_type.default",
            confidence="high",
            suggested_fix=(
                "Either update the spec default to match the API output, "
                "or normalise the API to return lowercase 'bearer'."
            ),
        ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_auth_required_false_drift(client, state, findings)          # 1
    _check_creation_status_codes(client, state, findings)              # 2–4
    _check_login_request_body_undocumented(client, state, findings)    # 5
    _check_logout_underdocumented(client, state, findings)             # 6
    _check_undocumented_response_fields(client, state, findings)       # 7
    _check_token_type_casing(client, state, findings)                  # 8

    return findings