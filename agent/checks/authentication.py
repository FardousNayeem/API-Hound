from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id


CATEGORY = "authentication"

_NO_TOKEN = None
_INVALID_TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.badSig000000"
_MALFORMED_TOKEN = "not-a-token-at-all"


def _make_finding(
    *,
    severity: str,
    endpoint: str,
    method: str,
    title: str,
    description: str,
    request_info: Dict[str, Any],
    response: APIResponse,
    reproduction: str,
    expected: str,
    actual: str,
    confidence: str = "high",
) -> Finding:
    return Finding(
        id=stable_finding_id(
            prefix="AUTH",
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
        spec_reference=f"paths.{endpoint}.{method.lower()}.security",
        confidence=confidence,
        suggested_fix=(
            "Return HTTP 401 with WWW-Authenticate header when credentials "
            "are missing or invalid."
        ),
    )


def _check_endpoint(
    client: APIClient,
    method: str,
    path: str,
    token_label: str,
    raw_token: Optional[str],
    json_body: Optional[Dict[str, Any]],
    findings: List[Finding],
) -> None:
    """
    Request a protected endpoint with missing/invalid/malformed credentials.
    A protected endpoint should reject these with 401 or 403.
    """
    resp = client.request(
        method,
        path,
        token=raw_token,
        json_body=json_body,
    )

    if resp.status_code in (401, 403):
        return

    severity = "critical" if resp.status_code in (200, 201, 204) else "high"

    token_desc = {
        "none": "no Authorization header",
        "invalid": "an invalid JWT (bad signature)",
        "malformed": "a malformed token (non-JWT string)",
    }.get(token_label, token_label)

    headers: Dict[str, str] = {}
    if token_label == "invalid":
        headers["Authorization"] = f"Bearer {_INVALID_TOKEN}"
    elif token_label == "malformed":
        headers["Authorization"] = f"Bearer {_MALFORMED_TOKEN}"

    title = f"{method} {path} accepts request with {token_desc}"

    findings.append(
        _make_finding(
            severity=severity,
            endpoint=path,
            method=method,
            title=title,
            description=(
                f"The endpoint {method} {path} returned HTTP {resp.status_code} "
                f"when called with {token_desc}. Authentication should be "
                f"enforced and unauthenticated or invalidly authenticated "
                f"requests should be rejected."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=curl_command(
                client.base_url,
                method,
                path,
                headers=headers if headers else None,
                body=json_body,
            ),
            expected="HTTP 401 Unauthorized or HTTP 403 Forbidden",
            actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
            confidence="high",
        )
    )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    post_id: int = (
        next(iter(state.created_post_ids.values()), None)
        or (state.discovered_post_ids[0] if state.discovered_post_ids else 1)
    )

    follow_target_id: int = (
        state.user_ids.get("bob")
        or state.user_ids.get("carol")
        or 2
    )

    protected: List[Tuple[str, str, Optional[Dict[str, Any]]]] = [
        ("POST", "/auth/logout", None),
        ("GET", "/users/me", None),
        ("PATCH", "/users/me", {"bio": "test"}),
        ("POST", "/posts", {"body": "auth test post"}),
        ("PATCH", f"/posts/{post_id}", {"body": "auth test edit"}),
        ("DELETE", f"/posts/{post_id}", None),
        ("POST", f"/posts/{post_id}/comments", {"body": "auth test comment"}),
        ("POST", f"/posts/{post_id}/like", None),
        ("DELETE", f"/posts/{post_id}/like", None),
        ("POST", f"/users/{follow_target_id}/follow", None),
        ("DELETE", f"/users/{follow_target_id}/follow", None),
    ]

    token_variants: List[Tuple[str, Optional[str]]] = [
        ("none", _NO_TOKEN),
        ("invalid", _INVALID_TOKEN),
        ("malformed", _MALFORMED_TOKEN),
    ]

    for method, path, body in protected:
        for label, token in token_variants:
            _check_endpoint(
                client=client,
                method=method,
                path=path,
                token_label=label,
                raw_token=token,
                json_body=body,
                findings=findings,
            )
        state.endpoints_tested += 1

    return findings