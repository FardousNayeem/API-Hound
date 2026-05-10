from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Set

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
) -> Finding:
    return Finding(
        id=f"CONS-{str(uuid.uuid4())[:8].upper()}",
        category="consistency",
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


def _curl(path: str, method: str = "GET", token_label: Optional[str] = None) -> str:
    auth = f" -H 'Authorization: Bearer <{token_label}_token>'" if token_label else ""
    return f"curl -X {method} https://backend-agent-test.onrender.com{path}{auth}"


# 1 & 3: Check post shape consistency
def _check_post_shape_consistency(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """GET /posts and GET /posts/{id} should return same post object shape."""
    post_id = (
        state.created_post_ids.get("alice")
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )
    if not post_id:
        return

    feed_resp   = client.get("/posts", params={"limit": 1})
    single_resp = client.get(f"/posts/{post_id}")
    state.endpoints_tested += 2

    if feed_resp.status_code != 200 or single_resp.status_code != 200:
        return
    if not isinstance(feed_resp.body, list) or not feed_resp.body:
        return
    if not isinstance(single_resp.body, dict):
        return

    feed_item   = feed_resp.body[0]
    single_item = single_resp.body

    if not isinstance(feed_item, dict):
        return

    feed_keys   = set(feed_item.keys())
    single_keys = set(single_item.keys())

    only_in_feed   = feed_keys - single_keys
    only_in_single = single_keys - feed_keys

    if only_in_feed or only_in_single:
        findings.append(_finding(
            endpoint="/posts",
            method="GET",
            severity="low",
            title="Inconsistent post shape between feed and single-post endpoints",
            description=(
                f"GET /posts (feed) and GET /posts/{{id}} return different "
                f"sets of fields for post objects. "
                + (f"Only in feed: {only_in_feed}. " if only_in_feed else "")
                + (f"Only in single: {only_in_single}." if only_in_single else "")
            ),
            request_info=feed_resp.request_info,
            response=feed_resp,
            reproduction=f"{_curl('/posts')} vs {_curl(f'/posts/{post_id}')}",
            expected="Same post object shape on both endpoints",
            actual=(
                f"Feed keys: {sorted(feed_keys)}, "
                f"Single keys: {sorted(single_keys)}"
            ),
            confidence="high",
            suggested_fix=(
                "Use the same post serialiser for both the feed and "
                "the single-post endpoint."
            ),
        ))


# 2 & 5: ID field type consistency
def _check_id_type_consistency(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """ID fields must always be integers, never strings."""
    post_id   = state.created_post_ids.get("alice")
    alice_id  = state.user_ids.get("alice")

    checks = []

    # User
    if alice_id:
        resp = client.get(f"/users/{alice_id}")
        state.endpoints_tested += 1
        if resp.status_code == 200 and isinstance(resp.body, dict):
            checks.append(("/users/{user_id}", "GET", resp, resp.body.get("id")))

    # Post
    if post_id:
        resp = client.get(f"/posts/{post_id}")
        state.endpoints_tested += 1
        if resp.status_code == 200 and isinstance(resp.body, dict):
            checks.append(("/posts/{post_id}", "GET", resp, resp.body.get("id")))

    # Comment
    if post_id:
        resp = client.get(f"/posts/{post_id}/comments")
        state.endpoints_tested += 1
        if (resp.status_code == 200
                and isinstance(resp.body, list)
                and resp.body
                and isinstance(resp.body[0], dict)):
            comment = resp.body[0]
            checks.append((
                "/posts/{post_id}/comments", "GET", resp,
                comment.get("id"),
            ))
            for field in ("post_id", "author_id"):
                val = comment.get(field)
                if val is not None and not isinstance(val, int):
                    findings.append(_finding(
                        endpoint="/posts/{post_id}/comments",
                        method="GET",
                        severity="medium",
                        title=f"CommentResponse.{field} is not an integer",
                        description=(
                            f"CommentResponse.{field} has value {val!r} "
                            f"of type {type(val).__name__}. "
                            f"The spec defines it as integer."
                        ),
                        request_info=resp.request_info,
                        response=resp,
                        reproduction=_curl(f"/posts/{post_id}/comments"),
                        expected=f"{field}: integer",
                        actual=f"{field}: {type(val).__name__} = {val!r}",
                        spec_reference="components.schemas.CommentResponse",
                        suggested_fix=f"Ensure {field} is serialised as an integer.",
                    ))

    for generic_path, method, resp, id_val in checks:
        if id_val is not None and not isinstance(id_val, int):
            findings.append(_finding(
                endpoint=generic_path,
                method=method,
                severity="medium",
                title=f"id field is not integer type on {method} {generic_path}",
                description=(
                    f"The 'id' field in {method} {generic_path} response is "
                    f"{type(id_val).__name__} ({id_val!r}). "
                    f"All id fields are defined as integer in the spec."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(generic_path.split("{")[0].rstrip("/")),
                expected="id: integer",
                actual=f"id: {type(id_val).__name__} = {id_val!r}",
                spec_reference=f"components.schemas.*",
                suggested_fix="Ensure all id fields are serialised as integers, not strings.",
            ))


# 4: Error envelope consistency
def _check_error_envelope(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Compare error response shapes across multiple error codes.
    Consistent APIs use the same top-level error envelope.
    """
    error_cases = {
        "404": client.get("/posts/999999999"),
        "422": client.post("/auth/login", json_body={}),
        "401": client.get("/users/me"),     # no token
    }
    state.endpoints_tested += 3

    shapes: Dict[str, Any] = {}
    sample_resp: Optional[APIResponse] = None

    for code_label, resp in error_cases.items():
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
        findings.append(_finding(
            endpoint="/posts/{post_id}",
            method="GET",
            severity="low",
            title="Error envelope is inconsistent across different error codes",
            description=(
                "Different error responses have completely different top-level keys, "
                "indicating no uniform error envelope is being used. "
                + " | ".join(f"{k}: {v}" for k, v in shapes.items())
            ),
            request_info=sample_resp.request_info,
            response=sample_resp,
            reproduction="Compare error responses from /posts/999999999 vs POST /auth/login {}",
            expected="All error responses share at least one common field (e.g. 'detail')",
            actual=f"Shapes: {shapes}",
            confidence="medium",
            suggested_fix=(
                "Use a single error response model across all endpoints. "
                "FastAPI's default {{detail: ...}} envelope is a good baseline."
            ),
        ))


# 6: Timestamp field naming
def _check_timestamp_naming(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    If timestamp fields exist, check for naming consistency.
    created_at vs createdAt vs timestamp vs date — mixed usage is a consistency bug.
    """
    post_id = (
        state.created_post_ids.get("alice")
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )
    if not post_id:
        return

    post_resp    = client.get(f"/posts/{post_id}")
    comment_resp = client.get(f"/posts/{post_id}/comments")
    state.endpoints_tested += 2

    ts_field_names: Dict[str, Set[str]] = {}

    snake_ts  = {"created_at", "updated_at", "deleted_at", "timestamp"}
    camel_ts  = {"createdAt", "updatedAt", "deletedAt"}
    other_ts  = {"date", "time", "created", "modified"}

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
        findings.append(_finding(
            endpoint="/posts/{post_id}",
            method="GET",
            severity="low",
            title="Inconsistent timestamp field naming: mixing snake_case and camelCase",
            description=(
                f"Timestamp fields use inconsistent naming conventions across "
                f"endpoints: {ts_field_names}. "
                f"Mixing snake_case (created_at) and camelCase (createdAt) "
                f"is inconsistent."
            ),
            request_info=post_resp.request_info,
            response=post_resp,
            reproduction=f"{_curl(f'/posts/{post_id}')} vs {_curl(f'/posts/{post_id}/comments')}",
            expected="Consistent timestamp field naming across all endpoints",
            actual=f"Mixed naming found: {ts_field_names}",
            confidence="medium",
            suggested_fix="Standardise all timestamp fields to snake_case (created_at) or camelCase (createdAt).",
        ))


# 7: Null vs absent field handling
def _check_null_vs_absent(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Optional fields like bio should be consistently null or absent.
    Check that GET /users/me and GET /users/{id} handle bio the same way.
    """
    alice_token = state.tokens.alice
    alice_id    = state.user_ids.get("alice")
    if not alice_token or not alice_id:
        return

    me_resp     = client.get("/users/me", token=alice_token)
    public_resp = client.get(f"/users/{alice_id}")
    state.endpoints_tested += 2

    if (me_resp.status_code != 200 or public_resp.status_code != 200
            or not isinstance(me_resp.body, dict)
            or not isinstance(public_resp.body, dict)):
        return

    me_has_bio     = "bio" in me_resp.body
    public_has_bio = "bio" in public_resp.body

    if me_has_bio != public_has_bio:
        findings.append(_finding(
            endpoint="/users/me",
            method="GET",
            severity="low",
            title="Inconsistent null/absent handling: 'bio' present in one endpoint but absent in other",
            description=(
                f"GET /users/me {'has' if me_has_bio else 'does not have'} "
                f"the 'bio' field, but GET /users/{alice_id} "
                f"{'has' if public_has_bio else 'does not have'} it. "
                f"Optional fields should be consistently null (not absent) across endpoints."
            ),
            request_info=me_resp.request_info,
            response=me_resp,
            reproduction=f"{_curl('/users/me', token_label='alice')} vs {_curl(f'/users/{alice_id}')}",
            expected="'bio' field present (as null) in both responses",
            actual=(
                f"/users/me bio={'present' if me_has_bio else 'absent'}, "
                f"/users/{alice_id} bio={'present' if public_has_bio else 'absent'}"
            ),
            confidence="medium",
            suggested_fix=(
                "Always include optional fields as null rather than omitting them. "
                "Use response_model_exclude_none=False in FastAPI."
            ),
        ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_post_shape_consistency(client, state, findings)  # 1 & 3
    _check_id_type_consistency(client, state, findings)     # 2 & 5
    _check_error_envelope(client, state, findings)          # 4
    _check_timestamp_naming(client, state, findings)        # 6
    _check_null_vs_absent(client, state, findings)          # 7

    return findings