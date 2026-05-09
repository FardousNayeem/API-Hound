from __future__ import annotations

import uuid
import json
from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding


# Finder function
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
        id=f"AUTHZ-{str(uuid.uuid4())[:8].upper()}",
        category="authorization",
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
        spec_reference=f"paths.{endpoint}.{method.lower()}",
        confidence=confidence,
        suggested_fix=suggested_fix or "Verify resource ownership against the authenticated user before allowing mutations.",
    )


def _curl(method: str, path: str, token_label: str, body: Optional[Dict] = None) -> str:
    body_flag = f" -d '{json.dumps(body)}'" if body else ""
    return (
        f"curl -X {method} https://backend-agent-test.onrender.com{path}"
        f" -H 'Authorization: Bearer <{token_label}_token>'"
        f" -H 'Content-Type: application/json'"
        f"{body_flag}"
    )


# Individual test functions
def _check_cross_user_post_edit(
    client: APIClient,
    state: SessionState,
    attacker: str,
    victim: str,
    findings: List[Finding],
) -> None:
    """Attacker tries to PATCH a post owned by victim."""
    victim_post_id = state.created_post_ids.get(victim)
    attacker_token = state.tokens.get(attacker)

    if not victim_post_id or not attacker_token:
        return

    path = f"/posts/{victim_post_id}"
    body = {"body": f"Overwritten by {attacker}"}
    resp = client.patch(path, token=attacker_token, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code not in (403, 404):
        findings.append(_finding(
            endpoint="/posts/{post_id}",
            method="PATCH",
            severity="critical" if resp.status_code in (200, 201) else "high",
            title=f"IDOR: {attacker} can edit {victim}'s post",
            description=(
                f"{attacker.capitalize()} sent PATCH /posts/{victim_post_id} "
                f"(owned by {victim}) and received HTTP {resp.status_code}. "
                f"The server should verify the authenticated user owns the post "
                f"before allowing edits."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("PATCH", path, attacker, body),
            expected="HTTP 403 Forbidden or 404 Not Found",
            actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
            suggested_fix="Check post.author_id == current_user.id before allowing PATCH.",
        ))


def _check_cross_user_post_delete(
    client: APIClient,
    state: SessionState,
    attacker: str,
    victim: str,
    findings: List[Finding],
) -> None:
    """Attacker tries to DELETE a post owned by victim."""
    victim_post_id = state.created_post_ids.get(victim)
    attacker_token = state.tokens.get(attacker)

    if not victim_post_id or not attacker_token:
        return

    path = f"/posts/{victim_post_id}"
    resp = client.delete(path, token=attacker_token)
    state.endpoints_tested += 1

    if resp.status_code not in (403, 404):
        findings.append(_finding(
            endpoint="/posts/{post_id}",
            method="DELETE",
            severity="critical" if resp.status_code in (200, 204) else "high",
            title=f"IDOR: {attacker} can delete {victim}'s post",
            description=(
                f"{attacker.capitalize()} sent DELETE /posts/{victim_post_id} "
                f"(owned by {victim}) and received HTTP {resp.status_code}. "
                f"Successful deletion of another user's post is a critical "
                f"authorization failure."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("DELETE", path, attacker),
            expected="HTTP 403 Forbidden or 404 Not Found",
            actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
            suggested_fix="Check post.author_id == current_user.id before allowing DELETE.",
        ))


def _check_idor_public_profile(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    GET /users/{id} must return UserPublic shape only: id, username, bio.
    Private fields email and role must NOT be present.
    """
    alice_id = state.user_ids.get("alice")
    if not alice_id:
        return

    path = f"/users/{alice_id}"
    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code != 200 or not isinstance(resp.body, dict):
        return

    private_fields_exposed = [
        field for field in ("email", "role", "age")
        if field in resp.body
    ]

    if private_fields_exposed:
        findings.append(_finding(
            endpoint="/users/{user_id}",
            method="GET",
            severity="high",
            title=f"IDOR: GET /users/{{id}} exposes private fields: {private_fields_exposed}",
            description=(
                f"GET /users/{alice_id} returned the following fields that "
                f"should only appear in the authenticated /users/me endpoint: "
                f"{private_fields_exposed}. "
                f"The spec defines UserPublic as containing only id, username, and bio. "
                f"Exposing email or role to unauthenticated callers is a privacy violation."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=f"curl https://backend-agent-test.onrender.com{path}",
            expected="Response contains only: id, username, bio",
            actual=f"Response also contains: {private_fields_exposed}. Full body: {str(resp.body)[:300]}",
            confidence="high",
            suggested_fix=(
                "Return the UserPublic schema from GET /users/{id}. "
                "Never serialize email or role into the public profile response."
            ),
        ))


def _check_privilege_escalation(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    PATCH /users/me with role=admin should not elevate the user's role.
    Verify by re-fetching /users/me and checking role is unchanged.
    """
    alice_token = state.tokens.alice
    if not alice_token:
        return

    me_resp = client.get("/users/me", token=alice_token)
    if me_resp.status_code != 200 or not isinstance(me_resp.body, dict):
        return
    original_role = me_resp.body.get("role", "user")

    path = "/users/me"
    body = {"role": "admin", "bio": "probe"}
    patch_resp = client.patch(path, token=alice_token, json_body=body)
    state.endpoints_tested += 1

    verify_resp = client.get("/users/me", token=alice_token)
    if verify_resp.status_code != 200 or not isinstance(verify_resp.body, dict):
        return

    new_role = verify_resp.body.get("role", original_role)

    if new_role != original_role:
        findings.append(_finding(
            endpoint="/users/me",
            method="PATCH",
            severity="critical",
            title="Privilege escalation: PATCH /users/me allows role to be changed",
            description=(
                f"Sending PATCH /users/me with {{\"role\": \"admin\"}} changed "
                f"alice's role from '{original_role}' to '{new_role}'. "
                f"The role field should be immutable via the profile update endpoint. "
                f"This is a critical privilege escalation vulnerability."
            ),
            request_info=patch_resp.request_info,
            response=patch_resp,
            reproduction=_curl("PATCH", path, "alice", body),
            expected=f"Role remains '{original_role}'; role field is ignored or rejected",
            actual=f"Role changed to '{new_role}'",
            suggested_fix=(
                "Whitelist only the fields users are allowed to update (bio, age). "
                "Never allow role, id, email, or username to be set via user-facing PATCH."
            ),
        ))
    elif patch_resp.status_code == 200:
        findings.append(_finding(
            endpoint="/users/me",
            method="PATCH",
            severity="medium",
            title="Mass assignment: PATCH /users/me silently accepts protected field 'role'",
            description=(
                f"Sending PATCH /users/me with {{\"role\": \"admin\"}} returned "
                f"HTTP {patch_resp.status_code} without rejecting the protected field. "
                f"Although the role did not change this time, silently accepting "
                f"protected fields is a mass assignment weakness that may be "
                f"exploitable if input filtering is inconsistent."
            ),
            request_info=patch_resp.request_info,
            response=patch_resp,
            reproduction=_curl("PATCH", path, "alice", body),
            expected="HTTP 400 or 422 rejecting the 'role' field as non-updatable",
            actual=f"HTTP {patch_resp.status_code}: request accepted without error",
            confidence="medium",
            suggested_fix=(
                "Explicitly reject or strip unrecognised/protected fields in the "
                "update schema (e.g. use a strict Pydantic model with only bio and age)."
            ),
        ))


def _check_mass_assignment_on_register(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    POST /auth/register with an extra role=admin field.
    If the API accepts it and the returned token decodes to admin role,
    that is a critical mass assignment bug.
    """
    import time
    unique_suffix = str(int(time.time()))[-6:]
    username = f"probe_user_{unique_suffix}"
    path = "/auth/register"
    body = {
        "username": username,
        "password": "probepass123",
        "email":    f"{username}@probe.test",
        "role":     "admin",
    }

    resp = client.post(path, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code not in (200, 201):
        return

    token = resp.body.get("access_token") if isinstance(resp.body, dict) else None
    if not token:
        return

    me_resp = client.get("/users/me", token=token)
    if me_resp.status_code == 200 and isinstance(me_resp.body, dict):
        actual_role = me_resp.body.get("role", "user")
        if actual_role == "admin":
            findings.append(_finding(
                endpoint="/auth/register",
                method="POST",
                severity="critical",
                title="Mass assignment on register: role=admin accepted at registration",
                description=(
                    f"POST /auth/register was sent with {{\"role\": \"admin\"}} "
                    f"and the created account has role='{actual_role}'. "
                    f"New users should always be assigned the default role server-side. "
                    f"Accepting role from request body is a critical privilege escalation."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=(
                    f"curl -X POST https://backend-agent-test.onrender.com/auth/register "
                    f"-H 'Content-Type: application/json' "
                    f"-d '{json.dumps(body)}'"
                ),
                expected="Account created with default role 'user', role field ignored",
                actual=f"Account created with role='{actual_role}'",
                suggested_fix=(
                    "Never read role from the registration payload. "
                    "Always assign the default role ('user') server-side on registration."
                ),
            ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_cross_user_post_edit(client, state, attacker="bob",   victim="alice", findings=findings)
    _check_cross_user_post_delete(client, state, attacker="bob", victim="alice", findings=findings)

    _check_cross_user_post_edit(client, state, attacker="carol",   victim="bob", findings=findings)
    _check_cross_user_post_delete(client, state, attacker="carol", victim="bob", findings=findings)

    _check_idor_public_profile(client, state, findings)

    _check_privilege_escalation(client, state, findings)

    _check_mass_assignment_on_register(client, state, findings)

    return findings