from __future__ import annotations

import time
import uuid
from typing import Any, Dict, List, Optional

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id, redacted_preview


CATEGORY = "authorization"


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
            prefix="AUTHZ",
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
        spec_reference=f"paths.{endpoint}.{method.lower()}",
        confidence=confidence,
        suggested_fix=(
            suggested_fix
            or "Verify resource ownership against the authenticated user before allowing mutations."
        ),
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


def _check_cross_user_post_edit(
    client: APIClient,
    state: SessionState,
    attacker: str,
    victim: str,
    findings: List[Finding],
) -> None:
    victim_post_id = state.created_post_ids.get(victim)
    attacker_token = state.tokens.get(attacker)

    if not victim_post_id or not attacker_token:
        return

    path = f"/posts/{victim_post_id}"
    body = {"body": f"Overwritten by {attacker}"}

    resp = client.patch(path, token=attacker_token, json_body=body)
    state.endpoints_tested += 1

    if resp.status_code not in (403, 404):
        findings.append(
            _finding(
                endpoint="/posts/{post_id}",
                method="PATCH",
                severity="critical" if resp.status_code in (200, 201) else "high",
                title=f"IDOR: {attacker} can edit {victim}'s post",
                description=(
                    f"{attacker.capitalize()} sent PATCH /posts/{victim_post_id}, "
                    f"which is owned by {victim}, and received HTTP {resp.status_code}. "
                    f"The server should verify the authenticated user owns the post "
                    f"before allowing edits."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "PATCH", path, attacker, body),
                expected="HTTP 403 Forbidden or 404 Not Found",
                actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                suggested_fix="Check post.author_id == current_user.id before allowing PATCH.",
            )
        )


def _check_cross_user_post_delete(
    client: APIClient,
    state: SessionState,
    attacker: str,
    victim: str,
    findings: List[Finding],
) -> None:
    victim_post_id = state.created_post_ids.get(victim)
    attacker_token = state.tokens.get(attacker)

    if not victim_post_id or not attacker_token:
        return

    path = f"/posts/{victim_post_id}"

    resp = client.delete(path, token=attacker_token)
    state.endpoints_tested += 1

    if resp.status_code not in (403, 404):
        findings.append(
            _finding(
                endpoint="/posts/{post_id}",
                method="DELETE",
                severity="critical" if resp.status_code in (200, 204) else "high",
                title=f"IDOR: {attacker} can delete {victim}'s post",
                description=(
                    f"{attacker.capitalize()} sent DELETE /posts/{victim_post_id}, "
                    f"which is owned by {victim}, and received HTTP {resp.status_code}. "
                    f"Successful deletion of another user's post is a critical "
                    f"authorization failure."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "DELETE", path, attacker),
                expected="HTTP 403 Forbidden or 404 Not Found",
                actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                suggested_fix="Check post.author_id == current_user.id before allowing DELETE.",
            )
        )


def _check_idor_public_profile(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    user_id = (
        state.user_ids.get("alice")
        or state.user_ids.get("bob")
        or state.user_ids.get("carol")
    )
    if not user_id:
        return

    path = f"/users/{user_id}"

    resp = client.get(path)
    state.endpoints_tested += 1

    if resp.status_code != 200 or not isinstance(resp.body, dict):
        return

    private_fields_exposed = [
        field for field in ("email", "role", "age")
        if field in resp.body
    ]

    if private_fields_exposed:
        findings.append(
            _finding(
                endpoint="/users/{user_id}",
                method="GET",
                severity="high",
                title=f"IDOR: GET /users/{{id}} exposes private fields: {private_fields_exposed}",
                description=(
                    f"GET /users/{user_id} returned fields that should not appear "
                    f"on the public user endpoint: {private_fields_exposed}. "
                    f"The public profile should expose only public fields."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, "GET", path),
                expected="Response contains only public profile fields such as id, username, and bio",
                actual=(
                    f"Response also contains: {private_fields_exposed}. "
                    f"Full body: {redacted_preview(resp.body, 300)}"
                ),
                confidence="high",
                suggested_fix=(
                    "Return the UserPublic schema from GET /users/{id}. "
                    "Never serialize email, role, age, password, or other private fields "
                    "into the public profile response."
                ),
            )
        )


def _check_privilege_escalation(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    user_label = next(
        (label for label in ("alice", "bob", "carol") if state.tokens.get(label)),
        None,
    )
    if not user_label:
        return

    token = state.tokens.get(user_label)
    if not token:
        return

    me_resp = client.get("/users/me", token=token)
    if me_resp.status_code != 200 or not isinstance(me_resp.body, dict):
        return

    original_role = me_resp.body.get("role", "user")

    path = "/users/me"
    body = {"role": "admin", "bio": "probe"}

    patch_resp = client.patch(path, token=token, json_body=body)
    state.endpoints_tested += 1

    verify_resp = client.get("/users/me", token=token)
    if verify_resp.status_code != 200 or not isinstance(verify_resp.body, dict):
        return

    new_role = verify_resp.body.get("role", original_role)

    if new_role != original_role:
        findings.append(
            _finding(
                endpoint="/users/me",
                method="PATCH",
                severity="critical",
                title="Privilege escalation: PATCH /users/me allows role to be changed",
                description=(
                    f"Sending PATCH /users/me with {{\"role\": \"admin\"}} changed "
                    f"{user_label}'s role from '{original_role}' to '{new_role}'. "
                    f"The role field should be immutable via the profile update endpoint."
                ),
                request_info=patch_resp.request_info,
                response=patch_resp,
                reproduction=_curl(client, "PATCH", path, user_label, body),
                expected=f"Role remains '{original_role}'; role field is ignored or rejected",
                actual=f"Role changed to '{new_role}'",
                suggested_fix=(
                    "Whitelist only the fields users are allowed to update. "
                    "Never allow role, id, email, username, or other protected fields "
                    "to be set via user-facing PATCH endpoints."
                ),
            )
        )
    elif patch_resp.status_code == 200:
        findings.append(
            _finding(
                endpoint="/users/me",
                method="PATCH",
                severity="medium",
                title="Mass assignment: PATCH /users/me silently accepts protected field 'role'",
                description=(
                    f"Sending PATCH /users/me with {{\"role\": \"admin\"}} returned "
                    f"HTTP {patch_resp.status_code} without rejecting the protected field. "
                    f"Although the role did not change, accepting protected fields silently "
                    f"is a mass-assignment weakness."
                ),
                request_info=patch_resp.request_info,
                response=patch_resp,
                reproduction=_curl(client, "PATCH", path, user_label, body),
                expected="HTTP 400 or 422 rejecting the 'role' field as non-updatable",
                actual=f"HTTP {patch_resp.status_code}: request accepted without error",
                confidence="medium",
                suggested_fix=(
                    "Explicitly reject or strip unrecognized and protected fields in "
                    "the update schema."
                ),
            )
        )


def _check_mass_assignment_on_register(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    username = f"probe_user_{uuid.uuid4().hex[:8]}"

    path = "/auth/register"
    body = {
        "username": username,
        "password": "probepass123",
        "email": f"{username}@probe.test",
        "role": "admin",
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
            findings.append(
                _finding(
                    endpoint="/auth/register",
                    method="POST",
                    severity="critical",
                    title="Mass assignment on register: role=admin accepted at registration",
                    description=(
                        f"POST /auth/register was sent with {{\"role\": \"admin\"}} "
                        f"and the created account has role='{actual_role}'. "
                        f"New users should always be assigned the default role server-side."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, "POST", path, body=body),
                    expected="Account created with default role 'user'; role field ignored or rejected",
                    actual=f"Account created with role='{actual_role}'",
                    suggested_fix=(
                        "Never read role from the registration payload. Always assign "
                        "the default role server-side during registration."
                    ),
                )
            )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_cross_user_post_edit(client, state, attacker="bob", victim="alice", findings=findings)
    _check_cross_user_post_delete(client, state, attacker="bob", victim="alice", findings=findings)

    _check_cross_user_post_edit(client, state, attacker="carol", victim="bob", findings=findings)
    _check_cross_user_post_delete(client, state, attacker="carol", victim="bob", findings=findings)

    _check_idor_public_profile(client, state, findings)
    _check_privilege_escalation(client, state, findings)
    _check_mass_assignment_on_register(client, state, findings)

    return findings