from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import httpx

from agent.client import APIClient, APIResponse
from agent.config import TIMEOUT
from agent.state import SessionState
from agent.models.report import Evidence, Finding
from agent.utils import curl_command, stable_finding_id, redact


CATEGORY = "headers_cors"


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
            prefix="HDR",
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
            request=redact(request_info),
            response=response.to_evidence_response(),
        ),
        reproduction=reproduction,
        expected=expected,
        actual=actual,
        spec_reference="",
        confidence=confidence,
        suggested_fix=suggested_fix,
    )


def _curl_headers(client: APIClient, path: str, extra: str = "") -> str:
    return f"curl -I {client.base_url.rstrip()}{path}{extra}"


def _curl_options(client: APIClient, path: str, origin: str) -> str:
    return (
        f"{curl_command(client.base_url, 'OPTIONS', path)} "
        f"-H 'Origin: {origin}' "
        f"-H 'Access-Control-Request-Method: POST' "
        f"-H 'Access-Control-Request-Headers: authorization,content-type'"
    )


def _get_baseline_response(
    client: APIClient,
    state: SessionState,
) -> Optional[APIResponse]:
    resp = client.get("/posts", params={"limit": 1})
    state.endpoints_tested += 1
    return resp if resp.status_code == 200 else None


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
        findings.append(
            _finding(
                endpoint="/posts",
                method="GET",
                severity="low",
                title="Missing security header: X-Content-Type-Options",
                description=(
                    "The response does not include the X-Content-Type-Options header. "
                    "Without this header, browsers may MIME-sniff responses."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl_headers(client, "/posts"),
                expected="X-Content-Type-Options: nosniff",
                actual="Header absent from response",
                suggested_fix="Add 'X-Content-Type-Options: nosniff' to all responses.",
            )
        )

    if "x-frame-options" not in headers:
        findings.append(
            _finding(
                endpoint="/posts",
                method="GET",
                severity="low",
                title="Missing security header: X-Frame-Options",
                description=(
                    "The response does not include the X-Frame-Options header. "
                    "This can allow the API to be embedded in iframes."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl_headers(client, "/posts"),
                expected="X-Frame-Options: DENY or SAMEORIGIN",
                actual="Header absent from response",
                suggested_fix="Add 'X-Frame-Options: DENY' or SAMEORIGIN to all responses.",
            )
        )

    if "strict-transport-security" not in headers:
        findings.append(
            _finding(
                endpoint="/posts",
                method="GET",
                severity="medium",
                title="Missing security header: Strict-Transport-Security (HSTS)",
                description=(
                    "The API does not send a Strict-Transport-Security header. "
                    "As this is an HTTPS API, HSTS should be enforced to prevent "
                    "protocol downgrade attacks."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl_headers(client, "/posts"),
                expected="Strict-Transport-Security: max-age=31536000; includeSubDomains",
                actual="Header absent from response",
                suggested_fix="Add HSTS header with a max-age of at least 1 year.",
            )
        )

    server_val = headers.get("server", "")
    if server_val and any(
        fw in server_val.lower()
        for fw in ["uvicorn", "gunicorn", "fastapi", "starlette", "nginx/", "apache/"]
    ):
        findings.append(
            _finding(
                endpoint="/posts",
                method="GET",
                severity="low",
                title=f"Server header discloses framework/version: '{server_val}'",
                description=(
                    f"The Server response header reveals implementation details: "
                    f"'{server_val}'. This can help attackers target known vulnerabilities."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl_headers(client, "/posts"),
                expected="Server header absent or generic",
                actual=f"Server: {server_val}",
                suggested_fix="Remove or replace the Server header with a generic value.",
            )
        )

    for leak_header in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
        if leak_header in headers:
            findings.append(
                _finding(
                    endpoint="/posts",
                    method="GET",
                    severity="low",
                    title=f"Info-disclosure header present: {leak_header}",
                    description=(
                        f"The response includes '{leak_header}: {headers[leak_header]}', "
                        f"which discloses implementation details."
                    ),
                    request_info=resp.request_info,
                    response=resp,
                    reproduction=_curl_headers(client, "/posts"),
                    expected=f"Header '{leak_header}' should not be present",
                    actual=f"{leak_header}: {headers[leak_header]}",
                    suggested_fix=f"Remove the '{leak_header}' response header.",
                )
            )


def _check_cors(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    path = "/posts"
    origin = "https://evil.example.com"

    start = time.perf_counter()
    try:
        with httpx.Client(timeout=TIMEOUT) as c:
            options_resp = c.options(
                client.base_url + path,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "authorization,content-type",
                },
            )
        elapsed_ms = (time.perf_counter() - start) * 1000
    except Exception:
        return

    state.endpoints_tested += 1

    resp_headers = {k.lower(): v for k, v in options_resp.headers.items()}
    acao = resp_headers.get("access-control-allow-origin", "")
    acac = resp_headers.get("access-control-allow-credentials", "")

    request_info = {
        "method": "OPTIONS",
        "url": client.base_url + path,
        "headers": {
            "Origin": origin,
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "authorization,content-type",
        },
        "body": None,
    }

    response = APIResponse(
        status_code=options_resp.status_code,
        headers=resp_headers,
        body=None,
        raw_text=options_resp.text,
        elapsed_ms=elapsed_ms,
        request_info=request_info,
    )

    if acao == "*":
        findings.append(
            _finding(
                endpoint=path,
                method="OPTIONS",
                severity="medium",
                title="CORS: Access-Control-Allow-Origin is wildcard (*)",
                description=(
                    "The API responds to cross-origin requests with "
                    "'Access-Control-Allow-Origin: *', allowing any origin to make "
                    "browser-based requests."
                ),
                request_info=request_info,
                response=response,
                reproduction=_curl_options(client, path, origin),
                expected="Specific allowed origin or no ACAO header",
                actual="Access-Control-Allow-Origin: *",
                suggested_fix="Restrict CORS to a whitelist of known trusted origins.",
            )
        )

    if acao == "*" and acac.lower() == "true":
        findings.append(
            _finding(
                endpoint=path,
                method="OPTIONS",
                severity="high",
                title="CORS: Wildcard origin combined with Allow-Credentials: true",
                description=(
                    "The API sets both 'Access-Control-Allow-Origin: *' and "
                    "'Access-Control-Allow-Credentials: true'. This indicates a "
                    "misconfigured CORS policy."
                ),
                request_info=request_info,
                response=response,
                reproduction=_curl_options(client, path, origin),
                expected="Credentials only allowed for specific trusted origins",
                actual=f"ACAO: {acao}, ACAC: {acac}",
                suggested_fix=(
                    "Never combine wildcard origin with Allow-Credentials: true. "
                    "Use an explicit origin whitelist."
                ),
            )
        )

    if acao == origin:
        findings.append(
            _finding(
                endpoint=path,
                method="OPTIONS",
                severity="high",
                title="CORS: Arbitrary Origin header is reflected in Allow-Origin",
                description=(
                    f"The API reflected attacker-supplied origin '{origin}' in "
                    f"Access-Control-Allow-Origin. This can allow arbitrary websites "
                    f"to make credentialed cross-origin requests."
                ),
                request_info=request_info,
                response=response,
                reproduction=_curl_options(client, path, origin),
                expected="Origin not reflected; only whitelisted origins allowed",
                actual=f"Access-Control-Allow-Origin: {acao}",
                suggested_fix="Validate Origin against an explicit whitelist before reflecting it.",
            )
        )


def _check_response_content_type(
    client: APIClient,
    state: SessionState,
    findings: List[Finding],
) -> None:
    resp = client.get("/posts", params={"limit": 1})
    state.endpoints_tested += 1

    if resp.status_code != 200:
        return

    ct = resp.headers.get("content-type", "")
    if "application/json" not in ct:
        findings.append(
            _finding(
                endpoint="/posts",
                method="GET",
                severity="low",
                title=f"Response Content-Type is not application/json: '{ct}'",
                description=(
                    f"GET /posts returned Content-Type: '{ct}' instead of "
                    f"'application/json'. JSON APIs should declare their content type."
                ),
                request_info=resp.request_info,
                response=resp,
                reproduction=_curl_headers(client, "/posts"),
                expected="Content-Type: application/json",
                actual=f"Content-Type: {ct}",
                suggested_fix="Set Content-Type: application/json on all JSON responses.",
            )
        )


def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []

    _check_security_headers(client, state, findings)
    _check_cors(client, state, findings)
    _check_response_content_type(client, state, findings)

    return findings