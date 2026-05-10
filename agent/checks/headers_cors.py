from __future__ import annotations

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
) -> Finding:
    return Finding(
        id=f"HDR-{str(uuid.uuid4())[:8].upper()}",
        category="headers_cors",
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


def _curl(path: str, extra: str = "") -> str:
    return f"curl -I https://backend-agent-test.onrender.com{path}{extra}"


# Probe a stable public endpoint for header checks
def _get_baseline_response(
    client: APIClient,
    state: SessionState,
) -> Optional[APIResponse]:
    resp = client.get("/posts", params={"limit": 1})
    state.endpoints_tested += 1
    return resp if resp.status_code == 200 else None


# 1–4: Security header presence
def _check_security_headers(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    resp = _get_baseline_response(client, state)
    if not resp:
        return

    headers = resp.headers

    if "x-content-type-options" not in headers:
        findings.append(_finding(
            endpoint="/posts",
            method="GET",
            severity="low",
            title="Missing security header: X-Content-Type-Options",
            description=(
                "The response does not include the X-Content-Type-Options header. "
                "Without this header, browsers may MIME-sniff responses, enabling "
                "content injection attacks."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("/posts"),
            expected="X-Content-Type-Options: nosniff",
            actual="Header absent from response",
            suggested_fix="Add 'X-Content-Type-Options: nosniff' to all responses.",
        ))

    if "x-frame-options" not in headers:
        findings.append(_finding(
            endpoint="/posts",
            method="GET",
            severity="low",
            title="Missing security header: X-Frame-Options",
            description=(
                "The response does not include the X-Frame-Options header. "
                "This can allow the API to be embedded in iframes, enabling "
                "clickjacking attacks."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("/posts"),
            expected="X-Frame-Options: DENY or SAMEORIGIN",
            actual="Header absent from response",
            suggested_fix="Add 'X-Frame-Options: DENY' to all responses.",
        ))

    if "strict-transport-security" not in headers:
        findings.append(_finding(
            endpoint="/posts",
            method="GET",
            severity="medium",
            title="Missing security header: Strict-Transport-Security (HSTS)",
            description=(
                "The API does not send a Strict-Transport-Security header. "
                "As this is an HTTPS API, HSTS should be enforced to prevent "
                "protocol downgrade and cookie hijacking attacks."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("/posts"),
            expected="Strict-Transport-Security: max-age=31536000; includeSubDomains",
            actual="Header absent from response",
            suggested_fix="Add HSTS header with a max-age of at least 1 year.",
        ))

    server_val = headers.get("server", "")
    if server_val and any(
        fw in server_val.lower()
        for fw in ["uvicorn", "gunicorn", "fastapi", "starlette", "nginx/", "apache/"]
    ):
        findings.append(_finding(
            endpoint="/posts",
            method="GET",
            severity="low",
            title=f"Server header discloses framework/version: '{server_val}'",
            description=(
                f"The Server response header reveals implementation details: "
                f"'{server_val}'. This aids attackers in targeting known "
                f"vulnerabilities for that specific server or framework version."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("/posts"),
            expected="Server header absent or generic (e.g. 'Server: app')",
            actual=f"Server: {server_val}",
            suggested_fix=(
                "Remove or replace the Server header. "
                "In uvicorn: use a custom middleware to overwrite it."
            ),
        ))

    for leak_header in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if leak_header in headers:
            findings.append(_finding(
                endpoint="/posts",
                method="GET",
                severity="low",
                title=f"Info-disclosure header present: {leak_header}",
                description=(
                    f"The response includes '{leak_header}: {headers[leak_header]}', "
                    f"which discloses implementation details to potential attackers."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl("/posts"),
                expected=f"Header '{leak_header}' should not be present",
                actual=f"{leak_header}: {headers[leak_header]}",
                suggested_fix=f"Remove the '{leak_header}' response header.",
            ))


# 5–7: CORS configuration
def _check_cors(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    import httpx
    from agent.config import BASE_URL, TIMEOUT

    path = "/posts"
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            options_resp = c.options(
                BASE_URL + path,
                headers={
                    "Origin":                         "https://evil.example.com",
                    "Access-Control-Request-Method":  "POST",
                    "Access-Control-Request-Headers": "authorization,content-type",
                },
            )
    except Exception:
        return
    state.endpoints_tested += 1

    resp_headers = {k.lower(): v for k, v in options_resp.headers.items()}
    acao = resp_headers.get("access-control-allow-origin", "")
    acac = resp_headers.get("access-control-allow-credentials", "")

    if acao == "*":
        findings.append(_finding(
            endpoint=path,
            method="OPTIONS",
            severity="medium",
            title="CORS: Access-Control-Allow-Origin is wildcard (*)",
            description=(
                "The API responds to cross-origin requests with "
                "'Access-Control-Allow-Origin: *', allowing any origin to "
                "make browser-based requests. For an API accepting credentials "
                "this is overly permissive."
            ),
            request_info={
                "method": "OPTIONS", "url": BASE_URL + path,
                "headers": {"Origin": "https://evil.example.com"},
                "body": None,
            },
            response=APIResponse(
                status_code=options_resp.status_code,
                headers=resp_headers,
                body=None,
                raw_text=options_resp.text,
                elapsed_ms=0,
                request_info={},
            ),
            reproduction=_curl(path, " -X OPTIONS -H 'Origin: https://evil.example.com'"),
            expected="Specific allowed origin or no ACAO header",
            actual=f"Access-Control-Allow-Origin: *",
            suggested_fix=(
                "Restrict CORS to a whitelist of known origins. "
                "Never use wildcard when credentials are involved."
            ),
        ))

    if acao == "*" and acac.lower() == "true":
        findings.append(_finding(
            endpoint=path,
            method="OPTIONS",
            severity="high",
            title="CORS: Wildcard origin combined with Allow-Credentials: true",
            description=(
                "The API sets both 'Access-Control-Allow-Origin: *' and "
                "'Access-Control-Allow-Credentials: true'. This combination "
                "is rejected by browsers (for security) but indicates a "
                "misconfigured CORS policy that could be exploited with "
                "non-standard clients."
            ),
            request_info={
                "method": "OPTIONS", "url": BASE_URL + path,
                "headers": {"Origin": "https://evil.example.com"},
                "body": None,
            },
            response=APIResponse(
                status_code=options_resp.status_code,
                headers=resp_headers,
                body=None,
                raw_text=options_resp.text,
                elapsed_ms=0,
                request_info={},
            ),
            reproduction=_curl(path, " -X OPTIONS -H 'Origin: https://evil.example.com'"),
            expected="Credentials must only be allowed for specific, trusted origins",
            actual=f"ACAO: {acao}, ACAC: {acac}",
            suggested_fix=(
                "Never combine wildcard origin with Allow-Credentials: true. "
                "Use an explicit origin whitelist."
            ),
        ))

    reflected_origin = "https://evil.example.com"
    if acao == reflected_origin:
        findings.append(_finding(
            endpoint=path,
            method="OPTIONS",
            severity="high",
            title="CORS: Arbitrary Origin header is reflected in Allow-Origin",
            description=(
                f"The API reflected the attacker-supplied origin "
                f"'{reflected_origin}' in the Access-Control-Allow-Origin header. "
                f"This allows any website to make credentialed cross-origin "
                f"requests to the API on behalf of authenticated users."
            ),
            request_info={
                "method": "OPTIONS", "url": BASE_URL + path,
                "headers": {"Origin": reflected_origin},
                "body": None,
            },
            response=APIResponse(
                status_code=options_resp.status_code,
                headers=resp_headers,
                body=None,
                raw_text=options_resp.text,
                elapsed_ms=0,
                request_info={},
            ),
            reproduction=_curl(path, f" -X OPTIONS -H 'Origin: {reflected_origin}'"),
            expected="Origin not reflected; only whitelisted origins allowed",
            actual=f"Access-Control-Allow-Origin: {acao}",
            suggested_fix="Validate the Origin header against an explicit whitelist before reflecting it.",
        ))


# 8: Content-Type on responses
def _check_response_content_type(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    resp = client.get("/posts", params={"limit": 1})
    if resp.status_code != 200:
        return

    ct = resp.headers.get("content-type", "")
    if "application/json" not in ct:
        findings.append(_finding(
            endpoint="/posts",
            method="GET",
            severity="low",
            title=f"Response Content-Type is not application/json: '{ct}'",
            description=(
                f"GET /posts returned Content-Type: '{ct}' instead of "
                f"'application/json'. JSON APIs should always declare "
                f"their content type explicitly."
            ),
            request_info=resp.request_info,
            response=resp,
            reproduction=_curl("/posts"),
            expected="Content-Type: application/json",
            actual=f"Content-Type: {ct}",
            suggested_fix="Set Content-Type: application/json on all JSON responses.",
        ))


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_security_headers(client, state, findings)       # 1–4
    _check_cors(client, state, findings)                   # 5–7
    _check_response_content_type(client, state, findings)  # 8

    return findings