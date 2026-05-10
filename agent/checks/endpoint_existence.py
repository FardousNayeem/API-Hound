from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional, Tuple

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
        id=f"EXIST-{str(uuid.uuid4())[:8].upper()}",
        category="endpoint_existence",
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


def _curl(path: str, method: str = "GET",
          token_label: Optional[str] = None) -> str:
    auth = f" -H 'Authorization: Bearer <{token_label}_token>'" if token_label else ""
    return f"curl -X {method} https://backend-agent-test.onrender.com{path}{auth}"


# 1: All documented endpoints exist check
def _check_documented_endpoints_exist(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    """
    Call every documented endpoint with valid parameters.
    DELETE /posts/{id} uses a dedicated sacrificial post so that
    comments/likes tests on alice's real post are not affected.
    """
    alice_token = state.tokens.alice
    bob_token   = state.tokens.bob
    post_id     = state.created_post_ids.get("alice") or 1
    alice_id    = state.user_ids.get("alice") or 1
    bob_id      = state.user_ids.get("bob") or 2

    delete_post_id = post_id
    if alice_token:
        r = client.post(
            "/posts",
            token=alice_token,
            json_body={"body": "Endpoint existence DELETE probe — disposable"},
        )
        if r.status_code in (200, 201) and isinstance(r.body, dict):
            pid = r.body.get("id")
            if pid:
                delete_post_id = int(pid)

    documented: List[Tuple[str, str, Optional[str], Optional[Dict], str]] = [
        # auth
        ("POST",   "/auth/login",    None,        {"username": "alice", "password": "alice123"}, "/auth/login"),
        ("POST",   "/auth/logout",   alice_token, None,                                          "/auth/logout"),
        # users
        ("GET",    "/users/me",      alice_token, None,                                          "/users/me"),
        ("PATCH",  "/users/me",      alice_token, {"bio": "existence probe"},                   "/users/me"),
        ("GET",    f"/users/{alice_id}", None,    None,                                          "/users/{user_id}"),
        # posts — read/write before any delete
        ("GET",    "/posts",         None,        None,                                          "/posts"),
        ("POST",   "/posts",         alice_token, {"body": "existence probe post"},              "/posts"),
        ("GET",    f"/posts/{post_id}",           None, None,                                    "/posts/{post_id}"),
        ("PATCH",  f"/posts/{post_id}",           alice_token, {"body": "existence probe edit"},"/posts/{post_id}"),
        # comments on alice's real post (before any delete)
        ("GET",    f"/posts/{post_id}/comments",  None, None,                                    "/posts/{post_id}/comments"),
        ("POST",   f"/posts/{post_id}/comments",  alice_token, {"body": "existence probe comment"}, "/posts/{post_id}/comments"),
        # likes on alice's real post (before any delete)
        ("POST",   f"/posts/{post_id}/like",      bob_token,   None,                             "/posts/{post_id}/like"),
        ("DELETE", f"/posts/{post_id}/like",      bob_token,   None,                             "/posts/{post_id}/like"),
        # follows
        ("POST",   f"/users/{bob_id}/follow",     alice_token, None,                             "/users/{user_id}/follow"),
        ("DELETE", f"/users/{bob_id}/follow",     alice_token, None,                             "/users/{user_id}/follow"),
        # meta
        ("GET",    "/",              None,        None,                                          "/"),
        # DELETE last — uses the dedicated sacrificial post
        ("DELETE", f"/posts/{delete_post_id}",    alice_token, None,                             "/posts/{post_id}"),
    ]

    for method, path, token, body, generic in documented:
        resp = client.request(method, path, token=token, json_body=body)
        state.endpoints_tested += 1

        if resp.status_code == 404:
            findings.append(_finding(
                endpoint=generic,
                method=method,
                severity="high",
                title=f"Documented endpoint missing: {method} {generic}",
                description=(
                    f"{method} {path} returned HTTP 404 Not Found. "
                    f"This endpoint is documented in the OpenAPI spec "
                    f"and should exist."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(path, method,
                                   "alice" if token == alice_token
                                   else "bob" if token == bob_token
                                   else None),
                expected=f"HTTP 200/201 (documented at {generic})",
                actual="HTTP 404 Not Found",
                spec_reference=f"paths.{generic}.{method.lower()}",
                suggested_fix=(
                    f"Verify the route {method} {generic} is registered "
                    f"in the application router."
                ),
            ))
        elif resp.status_code >= 500:
            findings.append(_finding(
                endpoint=generic,
                method=method,
                severity="high",
                title=f"Documented endpoint returns 5xx: {method} {generic}",
                description=(
                    f"{method} {path} returned HTTP {resp.status_code}. "
                    f"A documented endpoint should never return 5xx for a valid request."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl(path, method),
                expected="HTTP 200 or 201",
                actual=f"HTTP {resp.status_code}: {str(resp.body)[:200]}",
                spec_reference=f"paths.{generic}.{method.lower()}",
                suggested_fix="Investigate the server error on this route.",
            ))


# 2–8: Undocumented path probes
EXTENDED_PROBES: List[Tuple[str, str, str]] = [
    ("/docs",           "FastAPI Swagger UI",         "Exposes interactive API explorer in production"),
    ("/redoc",          "FastAPI ReDoc UI",           "Exposes API documentation in production"),
    ("/openapi.json",   "Raw OpenAPI spec",           "Exposes full API schema including internal details"),
    ("/admin",          "Admin panel",                "Admin interface should never be publicly accessible"),
    ("/debug",          "Debug endpoint",             "Debug endpoints leak internals"),
    ("/metrics",        "Metrics endpoint",           "Prometheus metrics expose server internals"),
    ("/health",         "Health check endpoint",      "May expose DB/service connection status"),
    ("/status",         "Status endpoint",            "May expose internal service state"),
    ("/v1/",            "API versioning prefix",      "Undocumented versioned routes may bypass security"),
    ("/v2/",            "API versioning prefix",      "Undocumented versioned routes may bypass security"),
    ("/api/",           "API prefix",                 "Undocumented API prefix routes"),
    ("/api/v1/",        "Versioned API prefix",       "Undocumented versioned API prefix"),
    ("/swagger",        "Swagger UI alternate path",  "Exposes API documentation in production"),
    ("/swagger-ui",     "Swagger UI alternate path",  "Exposes API documentation in production"),
    ("/.env",           "Environment file",           "Critical: exposes secrets and config"),
    ("/config",         "Config endpoint",            "May expose application configuration"),
    ("/users",          "Unslashed users route",      "May expose full user list without pagination"),
    ("/posts/",         "Trailing slash posts",       "Route inconsistency probe"),
    ("/../",            "Path traversal",             "Directory traversal attempt"),
    ("/%2e%2e/",        "Encoded path traversal",     "URL-encoded directory traversal"),
]

_SEVERITY_MAP: Dict[str, str] = {
    "/.env":          "critical",
    "/admin":         "critical",
    "/debug":         "high",
    "/config":        "high",
    "/metrics":       "medium",
    "/openapi.json":  "medium",
    "/docs":          "low",
    "/redoc":         "low",
    "/health":        "low",
    "/status":        "low",
}


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

        body_preview = resp.raw_text[:300]

        findings.append(_finding(
            endpoint=path,
            method="GET",
            severity=severity,
            title=f"Undocumented path accessible: GET {path} → HTTP {resp.status_code}",
            description=(
                f"GET {path} returned HTTP {resp.status_code}. "
                f"This path is not documented in the OpenAPI spec. "
                f"Concern: {concern}."
                + (f" Response: {body_preview}" if resp.status_code == 200 else "")
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl(path),
            expected="HTTP 404 — undocumented path should not be accessible",
            actual=f"HTTP {resp.status_code}: {body_preview[:150]}",
            confidence="high",
            suggested_fix=(
                f"If {path} is intentional, document it in the spec. "
                f"If it is a framework default ({label}), disable it in production."
            ),
        ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_documented_endpoints_exist(client, state, findings)   # 1
    _check_undocumented_paths(client, state, findings)           # 2–8

    return findings