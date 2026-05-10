from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id


CATEGORY = "consistency"


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
            prefix="CONS",
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
        spec_reference="",
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _curl(
    client: APIClient,
    path: str,
    method: str = "GET",
    token_label: Optional[str] = None,
) -> str:
    return curl_command(
        client.base_url,
        method,
        path,
        token_label=token_label,
    )


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


def _check_post_shape_consistency(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = _first_post_id(state)

    if not post_id:
        return

    feed_resp = client.get("/posts", params={"limit": 1})
    single_resp = client.get(f"/posts/{post_id}")
    state.endpoints_tested += 2

    if feed_resp.status_code != 200 or single_resp.status_code != 200:
        return
    if not isinstance(feed_resp.body, list) or not feed_resp.body:
        return
    if not isinstance(single_resp.body, dict):
        return

    feed_item = feed_resp.body[0]
    single_item = single_resp.body

    if not isinstance(feed_item, dict):
        return

    feed_keys = set(feed_item.keys())
    single_keys = set(single_item.keys())

    only_in_feed = feed_keys - single_keys
    only_in_single = single_keys - feed_keys

    if only_in_feed or only_in_single:
        title = "Inconsistent post shape between feed and single-post endpoints"
        findings.append(
            _finding(
                endpoint="/posts",
                method="GET",
                severity="low",
                title=title,
                description=(
                    "GET /posts and GET /posts/{id} return different field sets "
                    "for post objects. "
                    + (f"Only in feed: {sorted(only_in_feed)}. " if only_in_feed else "")
                    + (f"Only in single: {sorted(only_in_single)}." if only_in_single else "")
                ),
                request_info=feed_resp.request_info,
                response=feed_resp,
                reproduction=(
                    f"{_curl(client, '/posts')} vs "
                    f"{_curl(client, f'/posts/{post_id}')}"
                ),
                expected="Same post object shape on both endpoints",
                actual=f"Feed keys: {sorted(feed_keys)}, Single keys: {sorted(single_keys)}",
                confidence="high",
                suggested_fix="Use the same post serializer for both feed and single-post endpoints.",
            )
        )


def _check_id_type_consistency(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = _first_post_id(state)
    user_id = _first_user_id(state)

    checks: List[tuple[str, str, APIResponse, Any, str]] = []

    if user_id:
        resp = client.get(f"/users/{user_id}")
        state.endpoints_tested += 1
        if resp.status_code == 200 and isinstance(resp.body, dict):
            checks.append(("/users/{user_id}", "GET", resp, resp.body.get("id"), f"/users/{user_id}"))

    if post_id:
        resp = client.get(f"/posts/{post_id}")
        state.endpoints_tested += 1
        if resp.status_code == 200 and isinstance(resp.body, dict):
            checks.append(("/posts/{post_id}", "GET", resp, resp.body.get("id"), f"/posts/{post_id}"))

        resp = client.get(f"/posts/{post_id}/comments")
        state.endpoints_tested += 1
        if (
            resp.status_code == 200
            and isinstance(resp.body, list)
            and resp.body
            and isinstance(resp.body[0], dict)
        ):
            comment = resp.body[0]
            checks.append(
                (
                    "/posts/{post_id}/comments",
                    "GET",
                    resp,
                    comment.get("id"),
                    f"/posts/{post_id}/comments",
                )
            )

            for field in ("post_id", "author_id"):
                val = comment.get(field)
                if val is not None and not isinstance(val, int):
                    title = f"CommentResponse.{field} is not an integer"
                    findings.append(
                        _finding(
                            endpoint="/posts/{post_id}/comments",
                            method="GET",
                            severity="medium",
                            title=title,
                            description=(
                                f"CommentResponse.{field} has value {val!r} of "
                                f"type {type(val).__name__}. The spec defines it as integer."
                            ),
                            request_info=resp.request_info,
                            response=resp,
                            reproduction=_curl(client, f"/posts/{post_id}/comments"),
                            expected=f"{field}: integer",
                            actual=f"{field}: {type(val).__name__} = {val!r}",
                            suggested_fix=f"Ensure {field} is serialized as an integer.",
                        )
                    )

    for generic_path, method, resp, id_val, concrete_path in checks:
        if id_val is not None and not isinstance(id_val, int):
            title = f"id field is not integer type on {method} {generic_path}"
            findings.append(
                _finding(
                    endpoint=generic_path,
                    method=method,
                    severity="medium",
                    title=title,
                    description=(
                        f"The id field in {method} {generic_path} response is "
                        f"{type(id_val).__name__} ({id_val!r}). All id fields are "
                        f"defined as integer in the spec."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, concrete_path),
                    expected="id: integer",
                    actual=f"id: {type(id_val).__name__} = {id_val!r}",
                    suggested_fix="Ensure all id fields are serialized as integers, not strings.",
                )
            )


def _check_error_envelope(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    error_cases = {
        "404": client.get("/posts/999999999"),
        "422": client.post("/auth/login", json_body={}),
        "401": client.get("/users/me"),
    }
    state.endpoints_tested += 3

    shapes: Dict[str, Any] = {}
    sample_resp: Optional[APIResponse] = None

    for _, resp in error_cases.items():
        if resp.status_code not in (400, 401, 403, 404, 422):
            continue
        if isinstance(resp.body, dict):
            shapes[f"HTTP {resp.status_code}"] = sorted(resp.body.keys())
            sample_resp = resp

    if len(shapes) < 2 or not sample_resp:
        return

    all_key_sets = [set(v) for v in shapes.values()]
    common = all_key_sets[0].intersection(*all_key_sets[1:])

    if not common:
        title = "Error envelope is inconsistent across different error codes"
        findings.append(
            _finding(
                endpoint="/posts/{post_id}",
                method="GET",
                severity="low",
                title=title,
                description=(
                    "Different error responses have completely different top-level keys. "
                    + " | ".join(f"{k}: {v}" for k, v in shapes.items())
                ),
                request_info=sample_resp.request_info,
                response=sample_resp,
                reproduction=(
                    f"Compare {_curl(client, '/posts/999999999')} vs "
                    f"{curl_command(client.base_url, 'POST', '/auth/login', body={})}"
                ),
                expected="All error responses share at least one common field, such as detail",
                actual=f"Shapes: {shapes}",
                confidence="medium",
                suggested_fix="Use a single error response model across all endpoints.",
            )
        )


def _check_timestamp_naming(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id = _first_post_id(state)

    if not post_id:
        return

    post_resp = client.get(f"/posts/{post_id}")
    comment_resp = client.get(f"/posts/{post_id}/comments")
    state.endpoints_tested += 2

    ts_field_names: Dict[str, Set[str]] = {}

    snake_ts = {"created_at", "updated_at", "deleted_at", "timestamp"}
    camel_ts = {"createdAt", "updatedAt", "deletedAt"}
    other_ts = {"date", "time", "created", "modified"}

    all_ts = snake_ts | camel_ts | other_ts

    if post_resp.status_code == 200 and isinstance(post_resp.body, dict):
        found = {k for k in post_resp.body.keys() if k in all_ts}
        if found:
            ts_field_names["/posts/{id}"] = found

    if comment_resp.status_code == 200 and isinstance(comment_resp.body, list):
        for item in comment_resp.body:
            if isinstance(item, dict):
                found = {k for k in item.keys() if k in all_ts}
                if found:
                    ts_field_names["/comments"] = found
                break

    if len(ts_field_names) < 2:
        return

    all_found = set().union(*ts_field_names.values())
    has_snake = bool(all_found & snake_ts)
    has_camel = bool(all_found & camel_ts)

    if has_snake and has_camel:
        title = "Inconsistent timestamp field naming: mixing snake_case and camelCase"
        findings.append(
            _finding(
                endpoint="/posts/{post_id}",
                method="GET",
                severity="low",
                title=title,
                description=(
                    f"Timestamp fields use inconsistent naming conventions across "
                    f"endpoints: {ts_field_names}."
                ),
                request_info=post_resp.request_info,
                response=post_resp,
                reproduction=(
                    f"{_curl(client, f'/posts/{post_id}')} vs "
                    f"{_curl(client, f'/posts/{post_id}/comments')}"
                ),
                expected="Consistent timestamp field naming across all endpoints",
                actual=f"Mixed naming found: {ts_field_names}",
                confidence="medium",
                suggested_fix="Standardize timestamp fields to one convention.",
            )
        )


def _check_null_vs_absent(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    token_label, token = _first_valid_token(state)
    user_id = _first_user_id(state)

    if not token or not user_id:
        return

    me_resp = client.get("/users/me", token=token)
    public_resp = client.get(f"/users/{user_id}")
    state.endpoints_tested += 2

    if (
        me_resp.status_code != 200
        or public_resp.status_code != 200
        or not isinstance(me_resp.body, dict)
        or not isinstance(public_resp.body, dict)
    ):
        return

    me_has_bio = "bio" in me_resp.body
    public_has_bio = "bio" in public_resp.body

    if me_has_bio != public_has_bio:
        title = "Inconsistent null/absent handling: bio present in one endpoint but absent in other"
        findings.append(
            _finding(
                endpoint="/users/me",
                method="GET",
                severity="low",
                title=title,
                description=(
                    f"GET /users/me {'has' if me_has_bio else 'does not have'} "
                    f"the bio field, but GET /users/{user_id} "
                    f"{'has' if public_has_bio else 'does not have'} it."
                ),
                request_info=me_resp.request_info,
                response=me_resp,
                reproduction=(
                    f"{_curl(client, '/users/me', token_label=token_label)} vs "
                    f"{_curl(client, f'/users/{user_id}')}"
                ),
                expected="bio field present as null or string in both responses",
                actual=(
                    f"/users/me bio={'present' if me_has_bio else 'absent'}, "
                    f"/users/{user_id} bio={'present' if public_has_bio else 'absent'}"
                ),
                confidence="medium",
                suggested_fix="Always include optional fields consistently, or document when they are omitted.",
            )
        )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_post_shape_consistency(client, state, findings)
    _check_id_type_consistency(client, state, findings)
    _check_error_envelope(client, state, findings)
    _check_timestamp_naming(client, state, findings)
    _check_null_vs_absent(client, state, findings)

    return findings