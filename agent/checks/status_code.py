from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple, Type

from pydantic import BaseModel, ValidationError

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.api import (
    CommentResponse,
    TokenResponse,
    UserPrivate,
    UserPublic,
)
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
        id=f"SCHEMA-{str(uuid.uuid4())[:8].upper()}",
        category="schema_contract",
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


# Pydantic validation helper
def _validate_model(
    model_cls: Type[BaseModel],
    data: Any,
) -> Tuple[bool, List[str]]:
    """
    Try to parse data into model_cls.
    Returns (is_valid, list_of_error_strings).
    """
    try:
        model_cls.model_validate(data)
        return True, []
    except ValidationError as exc:
        errors = [f"{' → '.join(str(l) for l in e['loc'])}: {e['msg']}"
                  for e in exc.errors()]
        return False, errors


def _missing_required(model_cls: Type[BaseModel], data: Dict) -> List[str]:
    """Return required field names missing from data."""
    required = {
        name
        for name, field in model_cls.model_fields.items()
        if field.is_required()
    }
    return [f for f in required if f not in data]


def _unexpected_private_fields(data: Dict, forbidden: List[str]) -> List[str]:
    """Return field names from forbidden that are present in data."""
    return [f for f in forbidden if f in data]


# 1: POST /auth/login → TokenResponse
def _check_login_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/login"
    body = {"username": "alice", "password": "alice123"}
    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    if not isinstance(resp.body, dict):
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="high",
            title="POST /auth/login response is not a JSON object",
            description=(
                f"Expected a JSON object matching TokenResponse "
                f"(access_token, token_type) but got: {type(resp.body).__name__}."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, body=body),
            expected="JSON object with fields: access_token (str), token_type (str)",
            actual=f"Response body type: {type(resp.body).__name__}: {str(resp.body)[:200]}",
            spec_reference="components.schemas.TokenResponse",
            suggested_fix="Return a JSON object with access_token and token_type fields.",
        ))
        return

    is_valid, errors = _validate_model(TokenResponse, resp.body)
    if not is_valid:
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="high",
            title="POST /auth/login response does not match TokenResponse schema",
            description=(
                f"The response body failed validation against the TokenResponse "
                f"schema. Errors: {'; '.join(errors)}."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, body=body),
            expected="{ access_token: string, token_type: string }",
            actual=f"Validation errors: {errors}. Body: {str(resp.body)[:300]}",
            spec_reference="components.schemas.TokenResponse",
            suggested_fix="Ensure the login response serialises access_token as a string.",
        ))


# 2: POST /auth/register → TokenResponse(201)
def _check_register_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    import time
    path = "/auth/register"
    suffix = str(int(time.time()))[-6:]
    body = {
        "username": f"schema_probe_{suffix}",
        "password": "probepass99",
        "email":    f"schema_probe_{suffix}@test.local",
    }
    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code not in (200, 201):
        return

    if not isinstance(resp.body, dict):
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="high",
            title="POST /auth/register response is not a JSON object",
            description=(
                "Expected a JSON object with access_token (TokenResponse) "
                f"but got: {type(resp.body).__name__}."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, body=body),
            expected="{ access_token: string, token_type: string }",
            actual=f"{type(resp.body).__name__}: {str(resp.body)[:200]}",
            spec_reference="components.schemas.TokenResponse",
        ))
        return

    is_valid, errors = _validate_model(TokenResponse, resp.body)
    if not is_valid:
        findings.append(_finding(
            endpoint=path,
            method="POST",
            severity="high",
            title="POST /auth/register response does not match TokenResponse schema",
            description=(
                f"Register response failed TokenResponse validation. "
                f"Errors: {'; '.join(errors)}."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, body=body),
            expected="{ access_token: string, token_type: string }",
            actual=f"Validation errors: {errors}. Body: {str(resp.body)[:300]}",
            spec_reference="components.schemas.TokenResponse",
            suggested_fix="Return TokenResponse shape on successful registration.",
        ))


# 3: GET /users/me → UserPrivate
def _check_users_me_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token = state.tokens.alice
    if not token:
        return

    path = "/users/me"
    resp = client.get(path, token=token)
    state.endpoints_tested += 1

    if resp.status_code != 200 or not isinstance(resp.body, dict):
        return

    is_valid, errors = _validate_model(UserPrivate, resp.body)
    if not is_valid:
        missing = _missing_required(UserPrivate, resp.body)
        findings.append(_finding(
            endpoint=path,
            method="GET",
            severity="high",
            title="GET /users/me response does not match UserPrivate schema",
            description=(
                f"The /users/me response failed validation against UserPrivate. "
                f"Missing required fields: {missing if missing else 'none'}. "
                f"Validation errors: {'; '.join(errors)}."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path, "alice"),
            expected=(
                "{ id: int, username: str, email: str, role: str, "
                "age: int|null, bio: str|null }"
            ),
            actual=f"Errors: {errors}. Body keys: {list(resp.body.keys())}",
            spec_reference="components.schemas.UserPrivate",
            suggested_fix=(
                "Ensure /users/me serialises all required UserPrivate fields: "
                "id, username, email, role."
            ),
        ))


# 4: GET /users/{id} → UserPublic
def _check_user_by_id_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    alice_id = state.user_ids.get("alice")
    if not alice_id:
        return

    path = f"/users/{alice_id}"
    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code != 200 or not isinstance(resp.body, dict):
        return

    is_valid, errors = _validate_model(UserPublic, resp.body)
    if not is_valid:
        findings.append(_finding(
            endpoint="/users/{user_id}",
            method="GET",
            severity="medium",
            title="GET /users/{id} response does not match UserPublic schema",
            description=(
                f"GET /users/{alice_id} failed UserPublic validation. "
                f"Errors: {'; '.join(errors)}."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected="{ id: int, username: str, bio: str|null }",
            actual=f"Errors: {errors}. Body keys: {list(resp.body.keys())}",
            spec_reference="components.schemas.UserPublic",
            suggested_fix=(
                "Ensure GET /users/{id} returns only UserPublic fields: "
                "id, username, bio."
            ),
        ))

    private_leaked = _unexpected_private_fields(
        resp.body, ["email", "role", "password", "hashed_password"]
    )
    if private_leaked:
        findings.append(_finding(
            endpoint="/users/{user_id}",
            method="GET",
            severity="high",
            title=f"GET /users/{{id}} leaks private fields: {private_leaked}",
            description=(
                f"GET /users/{alice_id} returned private fields {private_leaked} "
                f"that are not part of the UserPublic schema. "
                f"These fields should only appear in the authenticated "
                f"GET /users/me endpoint."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected="Response contains only: id, username, bio",
            actual=f"Response also contains: {private_leaked}",
            spec_reference="components.schemas.UserPublic",
            suggested_fix=(
                "Use a separate serialiser/schema for the public profile endpoint. "
                "Never include email, role, or password in UserPublic responses."
            ),
        ))


# 5: GET /posts/{id}/comments → list[CmntRes]
def _check_comments_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = (
        state.created_post_ids.get("alice")
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )
    if not post_id:
        return

    alice_token = state.tokens.alice
    if alice_token:
        client.post(
            f"/posts/{post_id}/comments",
            token=alice_token,
            json_body={"body": "schema contract probe comment"},
        )

    path = f"/posts/{post_id}/comments"
    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    if not isinstance(resp.body, list):
        findings.append(_finding(
            endpoint="/posts/{post_id}/comments",
            method="GET",
            severity="high",
            title="GET /posts/{id}/comments does not return a JSON array",
            description=(
                f"The spec declares the response as array[CommentResponse] "
                f"but the body is: {type(resp.body).__name__}."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected="JSON array of CommentResponse objects",
            actual=f"Response type: {type(resp.body).__name__}: {str(resp.body)[:200]}",
            spec_reference=(
                "paths./posts/{post_id}/comments.get.responses.200.content"
                ".application/json.schema"
            ),
            suggested_fix="Return a JSON array from GET /posts/{id}/comments.",
        ))
        return

    invalid_items: List[Tuple[int, List[str]]] = []
    for i, item in enumerate(resp.body):
        if not isinstance(item, dict):
            invalid_items.append((i, [f"item is {type(item).__name__}, expected object"]))
            continue
        is_valid, errors = _validate_model(CommentResponse, item)
        if not is_valid:
            invalid_items.append((i, errors))

    if invalid_items:
        sample = invalid_items[:3]
        findings.append(_finding(
            endpoint="/posts/{post_id}/comments",
            method="GET",
            severity="medium",
            title="GET /posts/{id}/comments items do not match CommentResponse schema",
            description=(
                f"{len(invalid_items)} of {len(resp.body)} comment(s) failed "
                f"CommentResponse validation. "
                f"Required fields: id, post_id, author_id, body. "
                f"Sample errors (first {len(sample)}): "
                + "; ".join(f"[{i}] {e}" for i, errs in sample for e in errs)
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected=(
                "Array of { id: int, post_id: int, author_id: int, body: str }"
            ),
            actual=(
                f"{len(invalid_items)}/{len(resp.body)} items invalid. "
                f"Sample: {str(resp.body[:2])[:300]}"
            ),
            spec_reference="components.schemas.CommentResponse",
            suggested_fix=(
                "Serialise all required CommentResponse fields: "
                "id, post_id, author_id, body."
            ),
        ))


# 6: GET /posts → must be JSON array
def _check_posts_list_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/posts"
    resp = client.get(path, params={"limit": 5})
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    if not isinstance(resp.body, list):
        findings.append(_finding(
            endpoint=path,
            method="GET",
            severity="medium",
            title="GET /posts does not return a JSON array",
            description=(
                f"GET /posts returned a {type(resp.body).__name__} instead of "
                f"a JSON array. A paginated list endpoint should always return "
                f"an array at the top level."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected="JSON array of post objects",
            actual=f"Response type: {type(resp.body).__name__}: {str(resp.body)[:200]}",
            spec_reference="paths./posts.get.responses.200",
            suggested_fix="Return a top-level JSON array from GET /posts.",
        ))
        return

    if resp.body:
        sample = resp.body[0]
        missing = [f for f in ("id", "body") if f not in sample]
        if missing and isinstance(sample, dict):
            findings.append(_finding(
                endpoint=path,
                method="GET",
                severity="low",
                title=f"GET /posts items missing expected fields: {missing}",
                description=(
                    f"Post objects in the GET /posts feed are missing fields "
                    f"{missing}. Each post should at minimum expose id and body."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl("GET", path),
                expected="Each post object contains at least: id, body",
                actual=f"Sample item keys: {list(sample.keys()) if isinstance(sample, dict) else sample}",
                spec_reference="paths./posts.get.responses.200",
                confidence="medium",
                suggested_fix="Include id and body in every post object returned by the feed.",
            ))


# 7: GET /posts/{id} → post object
def _check_single_post_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = (
        state.created_post_ids.get("alice")
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )
    if not post_id:
        return

    path = f"/posts/{post_id}"
    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    if not isinstance(resp.body, dict):
        findings.append(_finding(
            endpoint="/posts/{post_id}",
            method="GET",
            severity="medium",
            title="GET /posts/{id} does not return a JSON object",
            description=(
                f"GET {path} returned {type(resp.body).__name__} "
                f"instead of a post object."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected="JSON object representing a post (id, body, author_id, ...)",
            actual=f"{type(resp.body).__name__}: {str(resp.body)[:200]}",
            spec_reference="paths./posts/{post_id}.get.responses.200",
            suggested_fix="Return a JSON object from GET /posts/{id}.",
        ))
        return

    missing = [f for f in ("id", "body") if f not in resp.body]
    if missing:
        findings.append(_finding(
            endpoint="/posts/{post_id}",
            method="GET",
            severity="medium",
            title=f"GET /posts/{{id}} response missing expected fields: {missing}",
            description=(
                f"GET {path} response is missing fields {missing}. "
                f"A post object must include at minimum id and body."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("GET", path),
            expected="Post object with at least: id, body",
            actual=f"Body keys present: {list(resp.body.keys())}",
            spec_reference="paths./posts/{post_id}.get.responses.200",
            suggested_fix="Include id and body in the single-post response.",
        ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_login_schema(client, state, findings)          # 1
    _check_register_schema(client, state, findings)       # 2
    _check_users_me_schema(client, state, findings)       # 3
    _check_user_by_id_schema(client, state, findings)     # 4
    _check_comments_schema(client, state, findings)       # 5
    _check_posts_list_schema(client, state, findings)     # 6
    _check_single_post_schema(client, state, findings)    # 7

    return findings