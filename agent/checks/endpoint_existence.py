from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from agent.client import APIClient, APIResponse
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id, redacted_preview


CATEGORY = "endpoint_existence"


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
            prefix="EXIST",
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
    path: str,
    method: str = "GET",
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


def _first_valid_token(state: SessionState) -> Tuple[Optional[str], Optional[str]]:
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


EXTENDED_PROBES: List[Tuple[str, str, str]] = [
    ("/docs", "FastAPI Swagger UI", "Exposes interactive API explorer in production"),
    ("/redoc", "FastAPI ReDoc UI", "Exposes API documentation in production"),
    ("/openapi.json", "Raw OpenAPI spec", "Exposes full API schema including internal details"),
    ("/admin", "Admin panel", "Admin interface should never be publicly accessible"),
    ("/debug", "Debug endpoint", "Debug endpoints leak internals"),
    ("/metrics", "Metrics endpoint", "Prometheus metrics expose server internals"),
    ("/health", "Health check endpoint", "May expose DB/service connection status"),
    ("/status", "Status endpoint", "May expose internal service state"),
    ("/v1/", "API versioning prefix", "Undocumented versioned routes may bypass security"),
    ("/v2/", "API versioning prefix", "Undocumented versioned routes may bypass security"),
    ("/api/", "API prefix", "Undocumented API prefix routes"),
    ("/api/v1/", "Versioned API prefix", "Undocumented versioned API prefix"),
    ("/swagger", "Swagger UI alternate path", "Exposes API documentation in production"),
    ("/swagger-ui", "Swagger UI alternate path", "Exposes API documentation in production"),
    ("/.env", "Environment file", "Critical: exposes secrets and config"),
    ("/config", "Config endpoint", "May expose application configuration"),
    ("/users", "Unslashed users route", "May expose full user list without pagination"),
    ("/posts/", "Trailing slash posts", "Route inconsistency probe"),
    ("/../", "Path traversal", "Directory traversal attempt"),
    ("/%2e%2e/", "Encoded path traversal", "URL-encoded directory traversal"),
]

_SEVERITY_MAP: Dict[str, str] = {
    "/.env": "critical",
    "/admin": "critical",
    "/debug": "high",
    "/config": "high",
    "/metrics": "medium",
    "/openapi.json": "medium",
    "/docs": "low",
    "/redoc": "low",
    "/health": "low",
    "/status": "low",
}


def _check_documented_endpoints_exist(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    actor_label, actor_token = _first_valid_token(state)
    user_id = _first_user_id(state)
    post_id = _first_post_id(state)

    login_body = {"username": "bob", "password": "bob123"}

    documented: List[Tuple[str, str, Optional[str], Optional[Dict[str, Any]], str, Optional[str]]] = [
        ("POST", "/auth/login", None, login_body, "/auth/login", None),
        ("GET", "/posts", None, None, "/posts", None),
        ("GET", "/", None, None, "/", None),
    ]

    if actor_token:
        documented.extend(
            [
                ("POST", "/auth/logout", actor_token, None, "/auth/logout", actor_label),
                ("GET", "/users/me", actor_token, None, "/users/me", actor_label),
                ("PATCH", "/users/me", actor_token, {"bio": "existence probe"}, "/users/me", actor_label),
                ("POST", "/posts", actor_token, {"body": "existence probe post"}, "/posts", actor_label),
            ]
        )

    if user_id is not None:
        documented.append(("GET", f"/users/{user_id}", None, None, "/users/{user_id}", None))

    if post_id is not None:
        documented.extend(
            [
                ("GET", f"/posts/{post_id}", None, None, "/posts/{post_id}", None),
                ("GET", f"/posts/{post_id}/comments", None, None, "/posts/{post_id}/comments", None),
            ]
        )

        if actor_token:
            documented.extend(
                [
                    (
                        "PATCH",
                        f"/posts/{post_id}",
                        actor_token,
                        {"body": "existence probe edit"},
                        "/posts/{post_id}",
                        actor_label,
                    ),
                    (
                        "POST",
                        f"/posts/{post_id}/comments",
                        actor_token,
                        {"body": "existence probe comment"},
                        "/posts/{post_id}/comments",
                        actor_label,
                    ),
                    ("POST", f"/posts/{post_id}/like", actor_token, None, "/posts/{post_id}/like", actor_label),
                    ("DELETE", f"/posts/{post_id}/like", actor_token, None, "/posts/{post_id}/like", actor_label),
                ]
            )

    if user_id is not None and actor_token:
        documented.extend(
            [
                ("POST", f"/users/{user_id}/follow", actor_token, None, "/users/{user_id}/follow", actor_label),
                ("DELETE", f"/users/{user_id}/follow", actor_token, None, "/users/{user_id}/follow", actor_label),
            ]
        )

    if actor_token:
        delete_post_id: Optional[int] = None
        create_resp = client.post(
            "/posts",
            token=actor_token,
            json_body={"body": "Endpoint existence DELETE probe disposable post"},
        )
        if create_resp.status_code in (200, 201) and isinstance(create_resp.body, dict):
            pid = create_resp.body.get("id")
            if pid is not None:
                delete_post_id = int(pid)

        if delete_post_id is not None:
            documented.append(
                (
                    "DELETE",
                    f"/posts/{delete_post_id}",
                    actor_token,
                    None,
                    "/posts/{post_id}",
                    actor_label,
                )
            )

    for method, path, token, body, generic, token_label in documented:
        resp = client.request(method, path, token=token, json_body=body)
        state.endpoints_tested += 1

        if resp.status_code == 404:
            title = f"Documented endpoint missing: {method} {generic}"
            findings.append(
                _finding(
                    endpoint=generic,
                    method=method,
                    severity="high",
                    title=title,
                    description=(
                        f"{method} {path} returned HTTP 404 Not Found. This endpoint "
                        f"is documented in the OpenAPI spec and should exist."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, path, method, token_label, body),
                    expected=f"HTTP 200/201/204 or documented client error for {method} {generic}",
                    actual="HTTP 404 Not Found",
                    spec_reference=f"paths.{generic}.{method.lower()}",
                    suggested_fix=f"Verify the route {method} {generic} is registered in the application router.",
                )
            )
        elif resp.status_code >= 500:
            title = f"Documented endpoint returns 5xx: {method} {generic}"
            findings.append(
                _finding(
                    endpoint=generic,
                    method=method,
                    severity="high",
                    title=title,
                    description=(
                        f"{method} {path} returned HTTP {resp.status_code}. A documented "
                        f"endpoint should not return 5xx for a valid request."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl(client, path, method, token_label, body),
                    expected="HTTP 200/201/204 or a documented 4xx client error",
                    actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body)}",
                    spec_reference=f"paths.{generic}.{method.lower()}",
                    suggested_fix="Investigate and handle the server error on this route.",
                )
            )


def _check_undocumented_paths(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    for path, label, concern in EXTENDED_PROBES:
        resp = client.get(path)
        state.endpoints_tested += 1

        if resp.status_code in (404, 0):
            continue

        severity = _SEVERITY_MAP.get(path, "low")

        raw = resp.raw_text.lower()
        if any(s in raw for s in ["password", "secret", "token", "api_key", "private_key"]):
            severity = "critical"
        elif any(s in raw for s in ["traceback", "exception", "sqlalchemy", "internal server"]):
            severity = "high"
        elif resp.status_code == 200 and path in ("/docs", "/redoc", "/openapi.json"):
            severity = "medium"

        body_preview = redacted_preview(resp.body, 150)
        title = f"Undocumented path accessible: GET {path} -> HTTP {resp.status_code}"

        findings.append(
            _finding(
                endpoint=path,
                method="GET",
                severity=severity,
                title=title,
                description=(
                    f"GET {path} returned HTTP {resp.status_code}. This path is not "
                    f"documented in the OpenAPI spec. Concern: {concern}."
                    + (f" Response: {body_preview}" if resp.status_code == 200 else "")
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(client, path),
                expected="HTTP 404 Not Found for undocumented paths, unless explicitly intended and documented",
                actual=f"HTTP {resp.status_code}: {redacted_preview(resp.body, 150)}",
                confidence="high",
                suggested_fix=(
                    f"If {path} is intentional, document it in the spec. If it is a "
                    f"framework default such as {label}, disable it in production."
                ),
            )
        )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_documented_endpoints_exist(client, state, findings)
    _check_undocumented_paths(client, state, findings)

    return findings