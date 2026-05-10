from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional


SENSITIVE_KEYS = {
    "authorization",
    "access_token",
    "token",
    "refresh_token",
    "password",
    "secret",
    "api_key",
    "private_key",
}


def stable_finding_id(
    prefix: str,
    category: str,
    method: str,
    endpoint: str,
    title: str,
) -> str:
    """
    Build a deterministic finding ID.

    This replaces uuid.uuid4() so the same bug produces the same ID across runs,
    satisfying the reproducibility requirement.
    """
    raw = f"{category}|{method.upper()}|{endpoint}|{title}"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


def redact(value: Any) -> Any:
    """
    Recursively redact sensitive values from dictionaries/lists before writing
    evidence or logs.

    This prevents access tokens, Authorization headers, passwords, and secrets
    from leaking into report.json or agent_log.txt.
    """
    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}

        for key, item in value.items():
            key_str = str(key)
            if key_str.lower() in SENSITIVE_KEYS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact(item)

        return redacted

    if isinstance(value, list):
        return [redact(item) for item in value]

    return value


def curl_command(
    base_url: str,
    method: str,
    path: str,
    *,
    token_label: Optional[str] = None,
    body: Optional[Any] = None,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Build a reproduction curl command using the runtime base URL.

    Use this everywhere instead of hardcoding:
        https://backend-agent-test.onrender.com
    """
    url = base_url.rstrip("/") + path

    if params:
        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{url}?{query}"

    parts = [f"curl -X {method.upper()} {url}"]

    if token_label:
        parts.append(f"-H 'Authorization: Bearer <{token_label}_token>'")

    if headers:
        for key, value in headers.items():
            parts.append(f"-H '{key}: {value}'")

    if body is not None:
        parts.append("-H 'Content-Type: application/json'")
        parts.append(f"-d '{json.dumps(body, ensure_ascii=False)}'")

    return " ".join(parts)


def token_label_for_value(state: Any, token: Optional[str]) -> Optional[str]:
    """
    Return alice/bob/carol for a token value, used in reproduction commands.
    """
    if not token:
        return None

    for user in ("alice", "bob", "carol"):
        if token == state.tokens.get(user):
            return user

    return None


def generic_endpoint(path: str) -> str:
    """
    Convert concrete API paths into report-friendly path templates.

    Examples:
        /posts/123              -> /posts/{post_id}
        /posts/123/comments     -> /posts/{post_id}/comments
        /posts/123/like         -> /posts/{post_id}/like
        /users/2                -> /users/{user_id}
        /users/2/follow         -> /users/{user_id}/follow
    """
    parts = path.strip("/").split("/")

    if len(parts) >= 2 and parts[0] == "posts" and parts[1].isdigit():
        parts[1] = "{post_id}"

    if len(parts) >= 2 and parts[0] == "users" and parts[1].isdigit():
        parts[1] = "{user_id}"

    return "/" + "/".join(parts) if parts != [""] else "/"