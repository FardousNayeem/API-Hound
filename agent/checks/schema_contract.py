from __future__ import annotations

import time
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
from agent.utils import curl_command, stable_finding_id


CATEGORY = "schema_contract"


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
            prefix="SCHEMA",
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


def _validate_model(
    model_cls: Type[BaseModel],
    data: Any,
) -> Tuple[bool, List[str]]:
    try:
        model_cls.model_validate(data)
        return True, []
    except ValidationError as exc:
        errors = [
            f"{' -> '.join(str(l) for l in e['loc'])}: {e['msg']}"
            for e in exc.errors()
        ]
        return False, errors


def _missing_required(model_cls: Type[BaseModel], data: Dict[str, Any]) -> List[str]:
    required = {
        name
        for name, field in model_cls.model_fields.items()
        if field.is_required()
    }
    return [f for f in required if f not in data]


def _unexpected_private_fields(data: Dict[str, Any], forbidden: List[str]) -> List[str]:
    return [f for f in forbidden if f in data]


def _first_valid_token(state: SessionState) -> tuple[Optional[str], Optional[str]]:
    for label in ("alice", "bob", "carol"):
        token = state.tokens.get(label)
        if token:
            return label, token
    return None, None


def _first_user_id(state: SessionState) -> Optional[int]:
    for label in ("alice", "bob", "carol"):
        uid = state.user_ids.get(label)
        if uid is not None:
            return uid
    return next(iter(state.user_ids.values()), None)


def _first_post_id(state: SessionState) -> Optional[int]:
    return (
        next(iter(state.created_post_ids.values()), None)
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )


def _check_login_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/login"
    body = {"username": "bob", "password": "bob123"}

    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    if not isinstance(resp.body, dict):
        title = "POST /auth/login response is not a JSON object"
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="high",
                title=title,
                description=(
                    f"Expected a JSON object matching TokenResponse but got "
                    f"{type(resp.body).__name__}."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "POST", path, body=body),
                expected="JSON object with access_token and optional token_type",
                actual=f"Response body type: {type(resp.body).__name__}: {str(resp.body)[:200]}",
                spec_reference="components.schemas.TokenResponse",
                suggested_fix="Return a JSON object with access_token and token_type fields.",
            )
        )
        return

    is_valid, errors = _validate_model(TokenResponse, resp.body)
    if not is_valid:
        title = "POST /auth/login response does not match TokenResponse schema"
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="high",
                title=title,
                description=(
                    "The response body failed validation against TokenResponse. "
                    f"Errors: {'; '.join(errors)}."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "POST", path, body=body),
                expected="{ access_token: string, token_type?: string }",
                actual=f"Validation errors: {errors}. Body: {str(resp.body)[:300]}",
                spec_reference="components.schemas.TokenResponse",
                suggested_fix="Ensure login response serializes access_token as a string.",
            )
        )


def _check_register_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/auth/register"
    suffix = str(int(time.time()))[-6:]

    body = {
        "username": f"schema_probe_{suffix}",
        "password": "probepass99",
        "email": f"schema_probe_{suffix}@test.local",
    }

    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code not in (200, 201):
        return

    if not isinstance(resp.body, dict):
        title = "POST /auth/register response is not a JSON object"
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="high",
                title=title,
                description=(
                    f"Expected a JSON object matching TokenResponse but got "
                    f"{type(resp.body).__name__}."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "POST", path, body=body),
                expected="{ access_token: string, token_type?: string }",
                actual=f"{type(resp.body).__name__}: {str(resp.body)[:200]}",
                spec_reference="components.schemas.TokenResponse",
                suggested_fix="Return TokenResponse shape on successful registration.",
            )
        )
        return

    is_valid, errors = _validate_model(TokenResponse, resp.body)
    if not is_valid:
        title = "POST /auth/register response does not match TokenResponse schema"
        findings.append(
            _finding(
                endpoint=path,
                method="POST",
                severity="high",
                title=title,
                description=(
                    f"Register response failed TokenResponse validation. "
                    f"Errors: {'; '.join(errors)}."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "POST", path, body=body),
                expected="{ access_token: string, token_type?: string }",
                actual=f"Validation errors: {errors}. Body: {str(resp.body)[:300]}",
                spec_reference="components.schemas.TokenResponse",
                suggested_fix="Return TokenResponse shape on successful registration.",
            )
        )


def _check_users_me_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _first_valid_token(state)

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
        title = "GET /users/me response does not match UserPrivate schema"
        findings.append(
            _finding(
                endpoint=path,
                method="GET",
                severity="high",
                title=title,
                description=(
                    f"The /users/me response failed validation against UserPrivate. "
                    f"Missing required fields: {missing if missing else 'none'}. "
                    f"Validation errors: {'; '.join(errors)}."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path, token_label),
                expected="{ id: int, username: str, email: str, role: str, age?: int|null, bio?: str|null }",
                actual=f"Errors: {errors}. Body keys: {list(resp.body.keys())}",
                spec_reference="components.schemas.UserPrivate",
                suggested_fix="Ensure /users/me serializes all required UserPrivate fields.",
            )
        )


def _check_user_by_id_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    user_id = _first_user_id(state)

    if not user_id:
        return

    path = f"/users/{user_id}"

    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code != 200 or not isinstance(resp.body, dict):
        return

    is_valid, errors = _validate_model(UserPublic, resp.body)
    if not is_valid:
        title = "GET /users/{id} response does not match UserPublic schema"
        findings.append(
            _finding(
                endpoint="/users/{user_id}",
                method="GET",
                severity="medium",
                title=title,
                description=(
                    f"GET /users/{user_id} failed UserPublic validation. "
                    f"Errors: {'; '.join(errors)}."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected="{ id: int, username: str, bio?: str|null }",
                actual=f"Errors: {errors}. Body keys: {list(resp.body.keys())}",
                spec_reference="components.schemas.UserPublic",
                suggested_fix="Ensure GET /users/{id} returns only UserPublic fields.",
            )
        )

    private_leaked = _unexpected_private_fields(
        resp.body,
        ["email", "role", "password", "hashed_password"],
    )

    if private_leaked:
        title = f"GET /users/{{id}} leaks private fields: {private_leaked}"
        findings.append(
            _finding(
                endpoint="/users/{user_id}",
                method="GET",
                severity="high",
                title=title,
                description=(
                    f"GET /users/{user_id} returned private fields {private_leaked} "
                    f"that are not part of the UserPublic schema."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected="Response contains only public fields: id, username, bio",
                actual=f"Response also contains: {private_leaked}",
                spec_reference="components.schemas.UserPublic",
                suggested_fix="Use a separate serializer/schema for the public profile endpoint.",
            )
        )


def _check_comments_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _first_valid_token(state)
    post_id = _first_post_id(state)

    if not post_id:
        return

    if token:
        client.post(
            f"/posts/{post_id}/comments",
            token=token,
            json_body={"body": "schema contract probe comment"},
        )

    path = f"/posts/{post_id}/comments"

    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    if not isinstance(resp.body, list):
        title = "GET /posts/{id}/comments does not return a JSON array"
        findings.append(
            _finding(
                endpoint="/posts/{post_id}/comments",
                method="GET",
                severity="high",
                title=title,
                description=(
                    f"The spec declares the response as array[CommentResponse], "
                    f"but the body is {type(resp.body).__name__}."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected="JSON array of CommentResponse objects",
                actual=f"Response type: {type(resp.body).__name__}: {str(resp.body)[:200]}",
                spec_reference="paths./posts/{post_id}/comments.get.responses.200.content.application/json.schema",
                suggested_fix="Return a JSON array from GET /posts/{id}/comments.",
            )
        )
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
        title = "GET /posts/{id}/comments items do not match CommentResponse schema"
        findings.append(
            _finding(
                endpoint="/posts/{post_id}/comments",
                method="GET",
                severity="medium",
                title=title,
                description=(
                    f"{len(invalid_items)} of {len(resp.body)} comment(s) failed "
                    f"CommentResponse validation. Sample errors: "
                    + "; ".join(f"[{i}] {e}" for i, errs in sample for e in errs)
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected="Array of { id: int, post_id: int, author_id: int, body: str }",
                actual=f"{len(invalid_items)}/{len(resp.body)} items invalid. Sample: {str(resp.body[:2])[:300]}",
                spec_reference="components.schemas.CommentResponse",
                suggested_fix="Serialize all required CommentResponse fields.",
            )
        )


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
        title = "GET /posts does not return a JSON array"
        findings.append(
            _finding(
                endpoint=path,
                method="GET",
                severity="medium",
                title=title,
                description=(
                    f"GET /posts returned a {type(resp.body).__name__} instead "
                    f"of a JSON array."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path, params={"limit": 5}),
                expected="JSON array of post objects",
                actual=f"Response type: {type(resp.body).__name__}: {str(resp.body)[:200]}",
                spec_reference="paths./posts.get.responses.200",
                suggested_fix="Return a top-level JSON array from GET /posts.",
            )
        )
        return

    if resp.body:
        sample = resp.body[0]
        if isinstance(sample, dict):
            missing = [f for f in ("id", "body") if f not in sample]
            if missing:
                title = f"GET /posts items missing expected fields: {missing}"
                findings.append(
                    _finding(
                        endpoint=path,
                        method="GET",
                        severity="low",
                        title=title,
                        description=(
                            f"Post objects in GET /posts are missing fields {missing}. "
                            f"Each post should at minimum expose id and body."
                        ),
                        request_info=resp.request_info,
                        response=resp,
                        reproduction=_curl(client, "GET", path, params={"limit": 5}),
                        expected="Each post object contains at least id and body",
                        actual=f"Sample item keys: {list(sample.keys())}",
                        spec_reference="paths./posts.get.responses.200",
                        confidence="medium",
                        suggested_fix="Include id and body in every post object returned by the feed.",
                    )
                )


def _check_single_post_schema(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = _first_post_id(state)

    if not post_id:
        return

    path = f"/posts/{post_id}"

    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    if not isinstance(resp.body, dict):
        title = "GET /posts/{id} does not return a JSON object"
        findings.append(
            _finding(
                endpoint="/posts/{post_id}",
                method="GET",
                severity="medium",
                title=title,
                description=f"GET {path} returned {type(resp.body).__name__} instead of a post object.",
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected="JSON object representing a post",
                actual=f"{type(resp.body).__name__}: {str(resp.body)[:200]}",
                spec_reference="paths./posts/{post_id}.get.responses.200",
                suggested_fix="Return a JSON object from GET /posts/{id}.",
            )
        )
        return

    missing = [f for f in ("id", "body") if f not in resp.body]
    if missing:
        title = f"GET /posts/{{id}} response missing expected fields: {missing}"
        findings.append(
            _finding(
                endpoint="/posts/{post_id}",
                method="GET",
                severity="medium",
                title=title,
                description=(
                    f"GET {path} response is missing fields {missing}. "
                    f"A post object must include at minimum id and body."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected="Post object with at least id and body",
                actual=f"Body keys present: {list(resp.body.keys())}",
                spec_reference="paths./posts/{post_id}.get.responses.200",
                suggested_fix="Include id and body in the single-post response.",
            )
        )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_login_schema(client, state, findings)
    _check_register_schema(client, state, findings)
    _check_users_me_schema(client, state, findings)
    _check_user_by_id_schema(client, state, findings)
    _check_comments_schema(client, state, findings)
    _check_posts_list_schema(client, state, findings)
    _check_single_post_schema(client, state, findings)

    return findings