from __future__ import annotations

import json
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
        id=f"BL-{str(uuid.uuid4())[:8].upper()}",
        category="business_logic",
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


def _curl(method: str, path: str, token_label: str,
          body: Optional[Dict] = None) -> str:
    body_flag = (
        f" -H 'Content-Type: application/json' -d '{json.dumps(body)}'"
        if body else ""
    )
    base = "https://backend-agent-test.onrender.com"
    return (
        f"curl -X {method} {base}{path}"
        f" -H 'Authorization: Bearer <{token_label}_token>'"
        f"{body_flag}"
    )


# 1: Follow yourself
def _check_follow_self(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    alice_id    = state.user_ids.get("alice")
    alice_token = state.tokens.alice
    if not alice_id or not alice_token:
        return

    path = f"/users/{alice_id}/follow"
    resp = client.post(path, token=alice_token)
    state.endpoints_tested += 1

    if resp.status_code in (200, 201, 204):
        findings.append(_finding(
            endpoint="/users/{user_id}/follow",
            method="POST",
            severity="medium",
            title="Business logic flaw: user can follow themselves",
            description=(
                f"POST /users/{alice_id}/follow with alice's own token "
                f"returned HTTP {resp.status_code}. "
                f"A user following themselves creates a nonsensical social graph "
                f"state and is a standard business logic flaw in social APIs."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("POST", path, "alice"),
            expected="HTTP 400 or 422 — cannot follow yourself",
            actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
            suggested_fix=(
                "Check that follower_id != followee_id before inserting "
                "the follow relationship. Return HTTP 400 with a clear message."
            ),
        ))


# 2: Double-follow
def _check_double_follow(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    bob_id      = state.user_ids.get("bob")
    carol_token = state.tokens.carol
    if not bob_id or not carol_token:
        return

    path = f"/users/{bob_id}/follow"

    resp1 = client.post(path, token=carol_token)
    state.endpoints_tested += 1

    if resp1.status_code not in (200, 201):
        return

    resp2 = client.post(path, token=carol_token)
    state.endpoints_tested += 1

    if resp2.status_code == 500:
        findings.append(_finding(
            endpoint="/users/{user_id}/follow",
            method="POST",
            severity="high",
            title="Double-follow causes HTTP 500 internal server error",
            description=(
                f"Following user {bob_id} twice as carol caused a 500 error on "
                f"the second request. The server should handle duplicate follow "
                f"attempts gracefully with 409 Conflict or idempotent 200."
            ),
            request_info=resp2.request_info,
            response=resp2,
            reproduction=(
                f"{_curl('POST', path, 'carol')}  # run twice in succession"
            ),
            expected="HTTP 409 Conflict or idempotent HTTP 200",
            actual=f"HTTP 500: {str(resp2.body)[:200]}",
            suggested_fix=(
                "Catch duplicate key / unique constraint violations in the follow "
                "handler and return 409 Conflict instead of propagating the exception."
            ),
        ))
    elif resp2.status_code not in (200, 201, 204, 409):
        findings.append(_finding(
            endpoint="/users/{user_id}/follow",
            method="POST",
            severity="medium",
            title=f"Double-follow returns unexpected HTTP {resp2.status_code}",
            description=(
                f"Following user {bob_id} twice as carol returned "
                f"HTTP {resp2.status_code} on the second request. "
                f"Expected either idempotent 200 or 409 Conflict."
            ),
            request_info=resp2.request_info,
            response=resp2,
            reproduction=(
                f"{_curl('POST', path, 'carol')}  # run twice in succession"
            ),
            expected="HTTP 200 (idempotent) or 409 Conflict",
            actual=f"HTTP {resp2.status_code}: {str(resp2.body)[:200]}",
            confidence="medium",
            suggested_fix="Handle duplicate follow attempts explicitly in the route handler.",
        ))


# 3: Unfollow never-followed user
def _check_unfollow_not_followed(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    alice_id    = state.user_ids.get("alice")
    carol_token = state.tokens.carol
    if not alice_id or not carol_token:
        return

    path = f"/users/{alice_id}/follow"
    resp = client.delete(path, token=carol_token)
    state.endpoints_tested += 1

    if resp.status_code == 500:
        findings.append(_finding(
            endpoint="/users/{user_id}/follow",
            method="DELETE",
            severity="high",
            title="Unfollow a non-followed user causes HTTP 500",
            description=(
                f"DELETE /users/{alice_id}/follow as carol (who never followed alice) "
                f"returned HTTP 500. The server crashed on a nonexistent relationship."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("DELETE", path, "carol"),
            expected="HTTP 404 Not Found — follow relationship does not exist",
            actual=f"HTTP 500: {str(resp.body)[:200]}",
            suggested_fix=(
                "Check that the follow relationship exists before deleting. "
                "Return 404 if it does not."
            ),
        ))
    elif resp.status_code in (200, 204):
        findings.append(_finding(
            endpoint="/users/{user_id}/follow",
            method="DELETE",
            severity="low",
            title="Unfollow a non-followed user returns success",
            description=(
                f"DELETE /users/{alice_id}/follow as carol returned "
                f"HTTP {resp.status_code} even though carol never followed alice. "
                f"While idempotent deletes are acceptable, this should be noted."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("DELETE", path, "carol"),
            expected="HTTP 404 Not Found or idempotent 200 with clear message",
            actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
            confidence="medium",
            suggested_fix="Return 404 when the follow relationship does not exist.",
        ))


# 4: Double-like
def _check_double_like(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id     = state.created_post_ids.get("alice")
    bob_token   = state.tokens.bob
    if not post_id or not bob_token:
        return

    path = f"/posts/{post_id}/like"

    resp1 = client.post(path, token=bob_token)
    state.endpoints_tested += 1

    if resp1.status_code not in (200, 201):
        return 

    resp2 = client.post(path, token=bob_token)
    state.endpoints_tested += 1

    if resp2.status_code == 500:
        findings.append(_finding(
            endpoint="/posts/{post_id}/like",
            method="POST",
            severity="high",
            title="Double-like causes HTTP 500 internal server error",
            description=(
                f"Liking post {post_id} twice as bob caused a 500 on the "
                f"second request. Duplicate likes should be handled gracefully."
            ),
            request_info=resp2.request_info,
            response=resp2,
            reproduction=f"{_curl('POST', path, 'bob')}  # run twice",
            expected="HTTP 409 Conflict or idempotent HTTP 200",
            actual=f"HTTP 500: {str(resp2.body)[:200]}",
            suggested_fix=(
                "Catch unique constraint violations in the like handler and "
                "return 409 Conflict."
            ),
        ))
    elif resp2.status_code not in (200, 201, 204, 409):
        findings.append(_finding(
            endpoint="/posts/{post_id}/like",
            method="POST",
            severity="medium",
            title=f"Double-like returns unexpected HTTP {resp2.status_code}",
            description=(
                f"Liking post {post_id} twice returned HTTP {resp2.status_code} "
                f"on the second attempt. Expected 409 Conflict or idempotent 200."
            ),
            request_info=resp2.request_info,
            response=resp2,
            reproduction=f"{_curl('POST', path, 'bob')}  # run twice",
            expected="HTTP 200 (idempotent) or 409 Conflict",
            actual=f"HTTP {resp2.status_code}: {str(resp2.body)[:200]}",
            confidence="medium",
            suggested_fix="Handle duplicate like attempts explicitly.",
        ))


# 5: Unlike never-liked post
def _check_unlike_never_liked(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    post_id     = state.created_post_ids.get("bob")
    carol_token = state.tokens.carol
    if not post_id or not carol_token:
        return

    path = f"/posts/{post_id}/like"
    resp = client.delete(path, token=carol_token)
    state.endpoints_tested += 1

    if resp.status_code == 500:
        findings.append(_finding(
            endpoint="/posts/{post_id}/like",
            method="DELETE",
            severity="high",
            title="Unlike a never-liked post causes HTTP 500",
            description=(
                f"DELETE /posts/{post_id}/like as carol (who never liked this post) "
                f"returned HTTP 500. Removing a nonexistent like crashed the server."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("DELETE", path, "carol"),
            expected="HTTP 404 Not Found — like does not exist",
            actual=f"HTTP 500: {str(resp.body)[:200]}",
            suggested_fix="Check that the like record exists before deleting it.",
        ))
    elif resp.status_code in (200, 204):
        findings.append(_finding(
            endpoint="/posts/{post_id}/like",
            method="DELETE",
            severity="low",
            title="Unlike a never-liked post returns success silently",
            description=(
                f"DELETE /posts/{post_id}/like as carol returned "
                f"HTTP {resp.status_code} even though carol never liked this post."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("DELETE", path, "carol"),
            expected="HTTP 404 Not Found",
            actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
            confidence="medium",
            suggested_fix="Return 404 when the like relationship does not exist.",
        ))


# 6: Delete same post twice
def _check_double_delete_post(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    carol_token = state.tokens.carol
    if not carol_token:
        return

    create_resp = client.post(
        "/posts",
        token=carol_token,
        json_body={"body": "Disposable post for double-delete test"},
    )
    if create_resp.status_code != 201 or not isinstance(create_resp.body, dict):
        return

    post_id = create_resp.body.get("id")
    if not post_id:
        return

    path = f"/posts/{post_id}"

    resp1 = client.delete(path, token=carol_token)
    state.endpoints_tested += 1

    if resp1.status_code not in (200, 204):
        return

    resp2 = client.delete(path, token=carol_token)
    state.endpoints_tested += 1

    if resp2.status_code == 500:
        findings.append(_finding(
            endpoint="/posts/{post_id}",
            method="DELETE",
            severity="high",
            title="Double-delete post causes HTTP 500",
            description=(
                f"Deleting post {post_id} twice caused a 500 on the second request. "
                f"Deleting an already-deleted resource should return 404."
            ),
            request_info=resp2.request_info,
            response=resp2,
            reproduction=f"{_curl('DELETE', path, 'carol')}  # run twice",
            expected="HTTP 404 Not Found on second delete",
            actual=f"HTTP 500: {str(resp2.body)[:200]}",
            suggested_fix="Return 404 when the post does not exist instead of propagating a DB error.",
        ))
    elif resp2.status_code in (200, 201, 204):
        findings.append(_finding(
            endpoint="/posts/{post_id}",
            method="DELETE",
            severity="medium",
            title="Double-delete post returns success on already-deleted resource",
            description=(
                f"Deleting post {post_id} twice returned HTTP {resp2.status_code} "
                f"on the second attempt. The post no longer exists so the server "
                f"should return 404."
            ),
            request_info=resp2.request_info,
            response=resp2,
            reproduction=f"{_curl('DELETE', path, 'carol')}  # run twice",
            expected="HTTP 404 Not Found on second delete",
            actual=f"HTTP {resp2.status_code}: {str(resp2.body)[:200]}",
            confidence="high",
            suggested_fix="Verify the post exists before deleting and return 404 if absent.",
        ))


# 7–10: Ghost resource actions
def _check_ghost_resources(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    alice_token = state.tokens.alice
    nonexistent_id = 999999999

    cases = [
        (
            "POST",
            f"/posts/{nonexistent_id}/comments",
            "Comment on nonexistent post",
            "/posts/{post_id}/comments",
            alice_token,
            {"body": "ghost comment"},
        ),
        (
            "POST",
            f"/posts/{nonexistent_id}/like",
            "Like a nonexistent post",
            "/posts/{post_id}/like",
            alice_token,
            None,
        ),
        (
            "POST",
            f"/users/{nonexistent_id}/follow",
            "Follow a nonexistent user",
            "/users/{user_id}/follow",
            alice_token,
            None,
        ),
        (
            "GET",
            f"/posts/{nonexistent_id}",
            "GET a nonexistent post",
            "/posts/{post_id}",
            None,
            None,
        ),
    ]

    for method, path, label, generic_path, token, body in cases:
        resp = client.request(method, path, token=token, json_body=body)
        state.endpoints_tested += 1

        if resp.status_code == 500:
            findings.append(_finding(
                endpoint=generic_path,
                method=method,
                severity="high",
                title=f"Ghost resource causes HTTP 500: {label}",
                description=(
                    f"{method} {path} returned HTTP 500. "
                    f"Accessing a nonexistent resource should return 404, "
                    f"not crash the server."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(method, path, "alice") if token else
                             f"curl -X {method} https://backend-agent-test.onrender.com{path}",
                expected="HTTP 404 Not Found",
                actual=f"HTTP 500: {str(resp.body)[:200]}",
                suggested_fix=(
                    "Add existence checks for all path parameters. "
                    "Return 404 when the referenced resource does not exist."
                ),
            ))
        elif resp.status_code not in (404, 403, 422):
            findings.append(_finding(
                endpoint=generic_path,
                method=method,
                severity="medium",
                title=f"Ghost resource returns unexpected status: {label}",
                description=(
                    f"{method} {path} returned HTTP {resp.status_code} "
                    f"for a nonexistent resource ID ({nonexistent_id}). "
                    f"Expected HTTP 404 Not Found."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(method, path, "alice") if token else
                             f"curl -X {method} https://backend-agent-test.onrender.com{path}",
                expected="HTTP 404 Not Found",
                actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
                confidence="high",
                suggested_fix="Return 404 for all references to nonexistent resource IDs.",
            ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_follow_self(client, state, findings)            # 1
    _check_double_follow(client, state, findings)          # 2
    _check_unfollow_not_followed(client, state, findings)  # 3
    _check_double_like(client, state, findings)            # 4
    _check_unlike_never_liked(client, state, findings)     # 5
    _check_double_delete_post(client, state, findings)     # 6
    _check_ghost_resources(client, state, findings)        # 7–10

    return findings