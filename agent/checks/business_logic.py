from __future__ import annotations

from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id


CATEGORY = "business_logic"


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
            prefix="BL",
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


def _check_follow_self(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    user_label = next(
        (label for label in ("alice", "bob", "carol") if state.tokens.get(label) and state.user_ids.get(label)),
        None,
    )
    if not user_label:
        return

    user_id = state.user_ids[user_label]
    token = state.tokens.get(user_label)
    if not token:
        return

    path = f"/users/{user_id}/follow"

    resp = client.post(path, token=token)
    state.endpoints_tested += 1

    if resp.status_code in (200, 201, 204):
        findings.append(
            _finding(
                endpoint="/users/{user_id}/follow",
                method="POST",
                severity="medium",
                title="Business logic flaw: user can follow themselves",
                description=(
                    f"POST /users/{user_id}/follow with {user_label}'s own token "
                    f"returned HTTP {resp.status_code}. A user following themselves "
                    f"creates an invalid social graph state."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "POST", path, user_label),
                expected="HTTP 400 or 422 — cannot follow yourself",
                actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
                suggested_fix=(
                    "Check that follower_id != followee_id before inserting the "
                    "follow relationship. Return HTTP 400 with a clear message."
                ),
            )
        )


def _check_double_follow(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label = next(
        (label for label in ("carol", "bob", "alice") if state.tokens.get(label)),
        None,
    )
    target_id = next(
        (
            uid
            for label, uid in state.user_ids.items()
            if label != actor_label
        ),
        None,
    )

    if not actor_label or not target_id:
        return

    token = state.tokens.get(actor_label)
    if not token:
        return

    path = f"/users/{target_id}/follow"

    resp1 = client.post(path, token=token)
    state.endpoints_tested += 1

    if resp1.status_code not in (200, 201, 204, 409):
        return

    resp2 = client.post(path, token=token)
    state.endpoints_tested += 1

    if resp2.status_code == 500:
        findings.append(
            _finding(
                endpoint="/users/{user_id}/follow",
                method="POST",
                severity="high",
                title="Double-follow causes HTTP 500 internal server error",
                description=(
                    f"Following user {target_id} twice as {actor_label} caused "
                    f"a 500 error on the second request. Duplicate follow attempts "
                    f"should be handled gracefully."
                ),
                request_info=resp2.request_info,
                response=resp2,
                reproduction=f"{_curl(client, 'POST', path, actor_label)}  # run twice in succession",
                expected="HTTP 409 Conflict or idempotent HTTP 200/204",
                actual=f"HTTP 500: {str(resp2.body)[:200]}",
                suggested_fix=(
                    "Catch duplicate key or unique constraint violations in the "
                    "follow handler and return 409 Conflict instead of propagating "
                    "the exception."
                ),
            )
        )
    elif resp2.status_code not in (200, 201, 204, 409):
        findings.append(
            _finding(
                endpoint="/users/{user_id}/follow",
                method="POST",
                severity="medium",
                title=f"Double-follow returns unexpected HTTP {resp2.status_code}",
                description=(
                    f"Following user {target_id} twice as {actor_label} returned "
                    f"HTTP {resp2.status_code} on the second request. Expected "
                    f"either idempotent success or 409 Conflict."
                ),
                request_info=resp2.request_info,
                response=resp2,
                reproduction=f"{_curl(client, 'POST', path, actor_label)}  # run twice in succession",
                expected="HTTP 200/204 idempotent success or 409 Conflict",
                actual=f"HTTP {resp2.status_code}: {str(resp2.body)[:200]}",
                confidence="medium",
                suggested_fix="Handle duplicate follow attempts explicitly in the route handler.",
            )
        )


def _check_unfollow_not_followed(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label = next(
        (label for label in ("carol", "bob", "alice") if state.tokens.get(label)),
        None,
    )
    target_id = next(
        (
            uid
            for label, uid in state.user_ids.items()
            if label != actor_label
        ),
        None,
    )

    if not actor_label or not target_id:
        return

    token = state.tokens.get(actor_label)
    if not token:
        return

    path = f"/users/{target_id}/follow"

    resp = client.delete(path, token=token)
    state.endpoints_tested += 1

    if resp.status_code == 500:
        findings.append(
            _finding(
                endpoint="/users/{user_id}/follow",
                method="DELETE",
                severity="high",
                title="Unfollow a non-followed user causes HTTP 500",
                description=(
                    f"DELETE /users/{target_id}/follow as {actor_label} returned "
                    f"HTTP 500. The server crashed on a nonexistent follow relationship."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "DELETE", path, actor_label),
                expected="HTTP 404 Not Found or idempotent HTTP 200/204",
                actual=f"HTTP 500: {str(resp.body)[:200]}",
                suggested_fix=(
                    "Check that the follow relationship exists before deleting. "
                    "Return 404 if it does not exist, or document idempotent delete behavior."
                ),
            )
        )
    elif resp.status_code in (200, 204):
        findings.append(
            _finding(
                endpoint="/users/{user_id}/follow",
                method="DELETE",
                severity="low",
                title="Unfollow a non-followed user returns success",
                description=(
                    f"DELETE /users/{target_id}/follow as {actor_label} returned "
                    f"HTTP {resp.status_code}. If the relationship did not exist, "
                    f"the API should either return 404 or explicitly document "
                    f"idempotent delete behavior."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "DELETE", path, actor_label),
                expected="HTTP 404 Not Found or documented idempotent success",
                actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
                confidence="medium",
                suggested_fix="Return 404 when the follow relationship does not exist, or document idempotency.",
            )
        )


def _check_double_like(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label = next(
        (label for label in ("bob", "carol", "alice") if state.tokens.get(label)),
        None,
    )
    post_id = (
        state.created_post_ids.get("alice")
        or state.created_post_ids.get("bob")
        or state.created_post_ids.get("carol")
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )

    if not actor_label or not post_id:
        return

    token = state.tokens.get(actor_label)
    if not token:
        return

    path = f"/posts/{post_id}/like"

    resp1 = client.post(path, token=token)
    state.endpoints_tested += 1

    if resp1.status_code not in (200, 201, 204, 409):
        return

    resp2 = client.post(path, token=token)
    state.endpoints_tested += 1

    if resp2.status_code == 500:
        findings.append(
            _finding(
                endpoint="/posts/{post_id}/like",
                method="POST",
                severity="high",
                title="Double-like causes HTTP 500 internal server error",
                description=(
                    f"Liking post {post_id} twice as {actor_label} caused a "
                    f"500 error on the second request. Duplicate likes should "
                    f"be handled gracefully."
                ),
                request_info=resp2.request_info,
                response=resp2,
                reproduction=f"{_curl(client, 'POST', path, actor_label)}  # run twice",
                expected="HTTP 409 Conflict or idempotent HTTP 200/204",
                actual=f"HTTP 500: {str(resp2.body)[:200]}",
                suggested_fix=(
                    "Catch unique constraint violations in the like handler and "
                    "return 409 Conflict or make the operation idempotent."
                ),
            )
        )
    elif resp2.status_code not in (200, 201, 204, 409):
        findings.append(
            _finding(
                endpoint="/posts/{post_id}/like",
                method="POST",
                severity="medium",
                title=f"Double-like returns unexpected HTTP {resp2.status_code}",
                description=(
                    f"Liking post {post_id} twice returned HTTP {resp2.status_code} "
                    f"on the second attempt. Expected 409 Conflict or idempotent success."
                ),
                request_info=resp2.request_info,
                response=resp2,
                reproduction=f"{_curl(client, 'POST', path, actor_label)}  # run twice",
                expected="HTTP 200/204 idempotent success or 409 Conflict",
                actual=f"HTTP {resp2.status_code}: {str(resp2.body)[:200]}",
                confidence="medium",
                suggested_fix="Handle duplicate like attempts explicitly.",
            )
        )


def _check_unlike_never_liked(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label = next(
        (label for label in ("carol", "bob", "alice") if state.tokens.get(label)),
        None,
    )
    post_id = (
        state.created_post_ids.get("bob")
        or state.created_post_ids.get("carol")
        or state.created_post_ids.get("alice")
        or (state.discovered_post_ids[0] if state.discovered_post_ids else None)
    )

    if not actor_label or not post_id:
        return

    token = state.tokens.get(actor_label)
    if not token:
        return

    path = f"/posts/{post_id}/like"

    resp = client.delete(path, token=token)
    state.endpoints_tested += 1

    if resp.status_code == 500:
        findings.append(
            _finding(
                endpoint="/posts/{post_id}/like",
                method="DELETE",
                severity="high",
                title="Unlike a never-liked post causes HTTP 500",
                description=(
                    f"DELETE /posts/{post_id}/like as {actor_label} returned "
                    f"HTTP 500. Removing a nonexistent like should not crash the server."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "DELETE", path, actor_label),
                expected="HTTP 404 Not Found or documented idempotent success",
                actual=f"HTTP 500: {str(resp.body)[:200]}",
                suggested_fix="Check that the like record exists before deleting it.",
            )
        )
    elif resp.status_code in (200, 204):
        findings.append(
            _finding(
                endpoint="/posts/{post_id}/like",
                method="DELETE",
                severity="low",
                title="Unlike a never-liked post returns success silently",
                description=(
                    f"DELETE /posts/{post_id}/like as {actor_label} returned "
                    f"HTTP {resp.status_code}. If no like existed, this should be "
                    f"documented as idempotent or return 404."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "DELETE", path, actor_label),
                expected="HTTP 404 Not Found or documented idempotent success",
                actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
                confidence="medium",
                suggested_fix="Return 404 when the like relationship does not exist, or document idempotency.",
            )
        )


def _check_double_delete_post(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label = next(
        (label for label in ("carol", "bob", "alice") if state.tokens.get(label)),
        None,
    )
    if not actor_label:
        return

    token = state.tokens.get(actor_label)
    if not token:
        return

    create_resp = client.post(
        "/posts",
        token=token,
        json_body={"body": "Disposable post for double-delete test"},
    )

    if create_resp.status_code not in (200, 201) or not isinstance(create_resp.body, dict):
        return

    post_id = create_resp.body.get("id")
    if not post_id:
        return

    path = f"/posts/{post_id}"

    resp1 = client.delete(path, token=token)
    state.endpoints_tested += 1

    if resp1.status_code not in (200, 204):
        return

    resp2 = client.delete(path, token=token)
    state.endpoints_tested += 1

    if resp2.status_code == 500:
        findings.append(
            _finding(
                endpoint="/posts/{post_id}",
                method="DELETE",
                severity="high",
                title="Double-delete post causes HTTP 500",
                description=(
                    f"Deleting post {post_id} twice caused a 500 on the second request. "
                    f"Deleting an already-deleted resource should return 404 or be "
                    f"explicitly documented as idempotent."
                ),
                request_info=resp2.request_info,
                response=resp2,
                reproduction=f"{_curl(client, 'DELETE', path, actor_label)}  # run twice",
                expected="HTTP 404 Not Found on second delete or documented idempotent success",
                actual=f"HTTP 500: {str(resp2.body)[:200]}",
                suggested_fix="Return 404 when the post does not exist instead of propagating an error.",
            )
        )
    elif resp2.status_code in (200, 201, 204):
        findings.append(
            _finding(
                endpoint="/posts/{post_id}",
                method="DELETE",
                severity="medium",
                title="Double-delete post returns success on already-deleted resource",
                description=(
                    f"Deleting post {post_id} twice returned HTTP {resp2.status_code} "
                    f"on the second attempt. The post no longer exists, so the API "
                    f"should return 404 or explicitly document idempotent delete behavior."
                ),
                request_info=resp2.request_info,
                response=resp2,
                reproduction=f"{_curl(client, 'DELETE', path, actor_label)}  # run twice",
                expected="HTTP 404 Not Found on second delete or documented idempotent success",
                actual=f"HTTP {resp2.status_code}: {str(resp2.body)[:200]}",
                confidence="high",
                suggested_fix="Verify the post exists before deleting and return 404 if absent.",
            )
        )


def _check_ghost_resources(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label = next(
        (label for label in ("alice", "bob", "carol") if state.tokens.get(label)),
        None,
    )
    actor_token = state.tokens.get(actor_label) if actor_label else None
    nonexistent_id = 999999999

    cases = [
        (
            "POST",
            f"/posts/{nonexistent_id}/comments",
            "Comment on nonexistent post",
            "/posts/{post_id}/comments",
            actor_token,
            actor_label,
            {"body": "ghost comment"},
        ),
        (
            "POST",
            f"/posts/{nonexistent_id}/like",
            "Like a nonexistent post",
            "/posts/{post_id}/like",
            actor_token,
            actor_label,
            None,
        ),
        (
            "POST",
            f"/users/{nonexistent_id}/follow",
            "Follow a nonexistent user",
            "/users/{user_id}/follow",
            actor_token,
            actor_label,
            None,
        ),
        (
            "GET",
            f"/posts/{nonexistent_id}",
            "GET a nonexistent post",
            "/posts/{post_id}",
            None,
            None,
            None,
        ),
    ]

    for method, path, label, generic_path, token, token_label, body in cases:
        resp = client.request(method, path, token=token, json_body=body)
        state.endpoints_tested += 1

        if resp.status_code == 500:
            findings.append(
                _finding(
                    endpoint=generic_path,
                    method=method,
                    severity="high",
                    title=f"Ghost resource causes HTTP 500: {label}",
                    description=(
                        f"{method} {path} returned HTTP 500. Accessing a "
                        f"nonexistent resource should return 404, not crash the server."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, method, path, token_label, body),
                    expected="HTTP 404 Not Found",
                    actual=f"HTTP 500: {str(resp.body)[:200]}",
                    suggested_fix=(
                        "Add existence checks for all path parameters and return "
                        "404 when the referenced resource does not exist."
                    ),
                )
            )
        elif resp.status_code not in (404, 403, 422):
            findings.append(
                _finding(
                    endpoint=generic_path,
                    method=method,
                    severity="medium",
                    title=f"Ghost resource returns unexpected status: {label}",
                    description=(
                        f"{method} {path} returned HTTP {resp.status_code} for "
                        f"a nonexistent resource ID ({nonexistent_id}). Expected "
                        f"HTTP 404 Not Found, 403 Forbidden, or 422 validation failure."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, method, path, token_label, body),
                    expected="HTTP 404 Not Found",
                    actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
                    confidence="high",
                    suggested_fix="Return 404 for all references to nonexistent resource IDs.",
                )
            )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_follow_self(client, state, findings)
    _check_double_follow(client, state, findings)
    _check_unfollow_not_followed(client, state, findings)
    _check_double_like(client, state, findings)
    _check_unlike_never_liked(client, state, findings)
    _check_double_delete_post(client, state, findings)
    _check_ghost_resources(client, state, findings)

    return findings