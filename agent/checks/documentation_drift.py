from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id


CATEGORY = "documentation_drift"


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
            prefix="DRIFT",
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
        spec_reference=spec_reference,
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _curl(
    client: APIClient,
    method: str,
    path: str,
    token_label: Optional[str] = None,
    body: Optional[Dict[str, Any]] = None,
) -> str:
    return curl_command(
        client.base_url,
        method,
        path,
        token_label=token_label,
        body=body,
    )


def _check_auth_required_false_drift(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/users/me"

    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code in (401, 403):
        findings.append(
            _finding(
                endpoint=path,
                method="GET",
                severity="medium",
                title="Spec drift: Authorization header marked required:false but endpoint enforces auth",
                description=(
                    f"The OpenAPI spec marks the Authorization header as "
                    f"'required: false' on GET /users/me and other protected "
                    f"endpoints. However, calling the endpoint without a token "
                    f"returns HTTP {resp.status_code}, proving auth is required."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected=(
                    "Spec should declare Authorization as required:true or use "
                    "a required bearer security scheme"
                ),
                actual=(
                    f"Spec says required:false, but API returns HTTP "
                    f"{resp.status_code} without auth"
                ),
                spec_reference="paths./users/me.get.parameters.authorization.required",
                confidence="high",
                suggested_fix=(
                    "Use OpenAPI security schemes such as BearerAuth instead of "
                    "manually declaring the Authorization header as an optional parameter."
                ),
            )
        )
    elif resp.status_code == 200:
        findings.append(
            _finding(
                endpoint=path,
                method="GET",
                severity="low",
                title="Spec drift: Authorization marked required:false and API does not enforce auth",
                description=(
                    "GET /users/me with no Authorization header returned HTTP 200. "
                    "The spec marks Authorization as required:false, which matches "
                    "observed behavior, but protected endpoints should require auth."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected="HTTP 401 Unauthorized; auth should be required",
                actual="HTTP 200 — endpoint accessible without auth",
                spec_reference="paths./users/me.get.parameters.authorization.required",
                confidence="high",
                suggested_fix="Mark Authorization as required in the spec and enforce it in the API.",
            )
        )


def _check_creation_status_codes(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label = next(
        (label for label in ("alice", "bob", "carol") if state.tokens.get(label)),
        None,
    )
    actor_token = state.tokens.get(actor_label) if actor_label else None

    post_id = (
        state.created_post_ids.get(actor_label) if actor_label else None
    ) or next(iter(state.created_post_ids.values()), None) or (
        state.discovered_post_ids[0] if state.discovered_post_ids else None
    )

    suffix = str(int(time.time()))[-5:]
    register_body = {
        "username": f"drift_{suffix}",
        "password": "driftpass99",
        "email": f"drift_{suffix}@test.local",
    }

    cases: List[Dict[str, Any]] = [
        {
            "method": "POST",
            "path": "/auth/register",
            "token": None,
            "token_label": None,
            "body": register_body,
            "expected_code": 201,
            "generic": "/auth/register",
            "spec_ref": "paths./auth/register.post.responses.201",
        }
    ]

    if actor_token:
        cases.append(
            {
                "method": "POST",
                "path": "/posts",
                "token": actor_token,
                "token_label": actor_label,
                "body": {"body": "documentation drift test post"},
                "expected_code": 201,
                "generic": "/posts",
                "spec_ref": "paths./posts.post.responses.201",
            }
        )

    if actor_token and post_id:
        cases.append(
            {
                "method": "POST",
                "path": f"/posts/{post_id}/comments",
                "token": actor_token,
                "token_label": actor_label,
                "body": {"body": "documentation drift test comment"},
                "expected_code": 201,
                "generic": "/posts/{post_id}/comments",
                "spec_ref": "paths./posts/{post_id}/comments.post.responses.201",
            }
        )

    for case in cases:
        method = case["method"]
        path = case["path"]
        token = case["token"]
        token_label = case["token_label"]
        body = case["body"]
        expected_code = case["expected_code"]
        generic = case["generic"]
        spec_ref = case["spec_ref"]

        resp = client.request(method, path, token=token, json_body=body)
        state.endpoints_tested += 1

        if resp.status_code == expected_code:
            continue

        if resp.status_code in (200, 201):
            findings.append(
                _finding(
                    endpoint=generic,
                    method=method,
                    severity="low",
                    title=(
                        f"Spec drift: {method} {generic} spec says "
                        f"{expected_code}, API returns {resp.status_code}"
                    ),
                    description=(
                        f"The OpenAPI spec documents HTTP {expected_code} for a "
                        f"successful {method} {generic}. The API returned HTTP "
                        f"{resp.status_code}. This is documentation drift."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, method, path, token_label, body),
                    expected=f"HTTP {expected_code} as documented in spec",
                    actual=f"HTTP {resp.status_code}",
                    spec_reference=spec_ref,
                    confidence="high",
                    suggested_fix=(
                        f"Either update the spec to document {resp.status_code}, "
                        f"or update the API to return {expected_code} for resource creation."
                    ),
                )
            )


def _check_login_request_body_undocumented(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/login"

    resp = client.post(path, json_body={})
    state.endpoints_tested += 1

    if resp.status_code in (400, 422):
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="medium",
                title="Spec drift: POST /auth/login has no requestBody in spec but API requires one",
                description=(
                    "The OpenAPI spec for POST /auth/login does not define a "
                    "requestBody schema. However, the API requires username and "
                    f"password fields and returns HTTP {resp.status_code} when "
                    "they are missing."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "POST", path, body={}),
                expected="Spec should define requestBody with username and password fields",
                actual=f"No requestBody in spec; API returns HTTP {resp.status_code} for missing fields",
                spec_reference="paths./auth/login.post.requestBody",
                confidence="high",
                suggested_fix=(
                    "Add a requestBody schema to POST /auth/login with username "
                    "and password fields marked as required."
                ),
            )
        )


def _check_logout_underdocumented(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label = next(
        (label for label in ("alice", "bob", "carol") if state.tokens.get(label)),
        None,
    )
    if not actor_label:
        return

    token = state.tokens.get(actor_label)
    if not token:
        return

    path = "/auth/logout"

    resp = client.post(path, token=token)
    state.endpoints_tested += 1

    if resp.status_code == 200 and isinstance(resp.body, dict) and resp.body:
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="low",
                title="Spec drift: POST /auth/logout returns fields but spec documents empty response {}",
                description=(
                    f"POST /auth/logout returned HTTP 200 with body {resp.body}. "
                    f"The spec defines the response schema as empty {{}}."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "POST", path, actor_label),
                expected="Empty JSON body {} as per spec",
                actual=f"Body contains: {list(resp.body.keys())}",
                spec_reference="paths./auth/logout.post.responses.200",
                confidence="medium",
                suggested_fix="Update the spec to document the actual logout response schema.",
            )
        )


def _check_undocumented_response_fields(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    user_id = (
        state.user_ids.get("alice")
        or state.user_ids.get("bob")
        or state.user_ids.get("carol")
    )

    if user_id:
        path = f"/users/{user_id}"
        resp = client.get(path)
        state.endpoints_tested += 1

        if resp.status_code == 200 and isinstance(resp.body, dict):
            documented_public = {"id", "username", "bio"}
            extra = set(resp.body.keys()) - documented_public

            if extra:
                findings.append(
                    _finding(
                        endpoint="/users/{user_id}",
                        method="GET",
                        severity="medium",
                        title=f"Spec drift: GET /users/{{id}} returns undocumented fields: {sorted(extra)}",
                        description=(
                            f"GET /users/{user_id} returned fields {sorted(extra)} "
                            f"that are not defined in the UserPublic schema. "
                            f"The spec only documents id, username, and bio."
                        ),
                        request_info=resp.request_info,
                        response=resp,
                        reproduction=_curl(client, "GET", path),
                        expected="Response contains only: id, username, bio",
                        actual=f"Extra undocumented fields: {sorted(extra)}",
                        spec_reference="components.schemas.UserPublic",
                        confidence="high",
                        suggested_fix=(
                            "Use an explicit response_model=UserPublic in the route "
                            "decorator to strip undocumented fields."
                        ),
                    )
                )

    post_id = (
        next(iter(state.created_post_ids.values()), None)
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )

    if not post_id:
        return

    comment_path = f"/posts/{post_id}/comments"
    comment_resp = client.get(comment_path)
    state.endpoints_tested += 1

    if (
        comment_resp.status_code == 200
        and isinstance(comment_resp.body, list)
        and comment_resp.body
        and isinstance(comment_resp.body[0], dict)
    ):
        documented_comment = {"id", "post_id", "author_id", "body"}
        extra_c = set(comment_resp.body[0].keys()) - documented_comment

        if extra_c:
            findings.append(
                _finding(
                    endpoint="/posts/{post_id}/comments",
                    method="GET",
                    severity="low",
                    title=f"Spec drift: comment response contains undocumented fields: {sorted(extra_c)}",
                    description=(
                        f"CommentResponse objects contain fields {sorted(extra_c)} "
                        f"not defined in the spec schema. Documented fields are "
                        f"id, post_id, author_id, and body."
                    ),
                    request_info=comment_resp.request_info,
                    response=comment_resp,
                    reproduction=_curl(client, "GET", comment_path),
                    expected="CommentResponse contains only: id, post_id, author_id, body",
                    actual=f"Extra fields: {sorted(extra_c)}",
                    spec_reference="components.schemas.CommentResponse",
                    confidence="high",
                    suggested_fix="Use response_model=CommentResponse to strip undocumented fields.",
                )
            )


def _check_token_type_casing(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/login"
    body = {"username": "alice", "password": "alice123"}

    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code != 200 or not isinstance(resp.body, dict):
        return

    token_type = resp.body.get("token_type")

    if token_type and token_type != "bearer":
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="low",
                title=f"Spec drift: token_type is '{token_type}', spec default is 'bearer'",
                description=(
                    f"POST /auth/login returned token_type: '{token_type}'. "
                    f"The OpenAPI spec defines the default as 'bearer' lowercase."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "POST", path, body=body),
                expected="token_type: 'bearer' as per spec default",
                actual=f"token_type: '{token_type}'",
                spec_reference="components.schemas.TokenResponse.properties.token_type.default",
                confidence="high",
                suggested_fix=(
                    "Either update the spec default to match the API output, "
                    "or normalize the API to return lowercase 'bearer'."
                ),
            )
        )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_auth_required_false_drift(client, state, findings)
    _check_creation_status_codes(client, state, findings)
    _check_login_request_body_undocumented(client, state, findings)
    _check_logout_underdocumented(client, state, findings)
    _check_undocumented_response_fields(client, state, findings)
    _check_token_type_casing(client, state, findings)

    return findings