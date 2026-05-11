from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Optional


SENSITIVE_KEYS = {
    "authorization",
    "access_token",
    "token",
    "refresh_token",
    "password",
    "password_hash",
    "secret",
    "api_key",
    "private_key",
}


JWT_RE = re.compile(
    r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
)

BCRYPT_RE = re.compile(
    r"\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}"
)


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: Dict[str, Any] = {}

        for key, item in value.items():
            key_str = str(key).lower()

            if key_str in SENSITIVE_KEYS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact(item)

        return redacted

    if isinstance(value, list):
        return [redact(item) for item in value]

    if isinstance(value, str):
        value = JWT_RE.sub("[REDACTED_JWT]", value)
        value = BCRYPT_RE.sub("[REDACTED_HASH]", value)
        return value

    return value

def redacted_preview(value: Any, max_chars: int = 200) -> str:
    safe_value = redact(value)
    text = str(safe_value)

    if len(text) > max_chars:
        return text[:max_chars]

    return text

def stable_finding_id(
    prefix: str,
    category: str,
    method: str,
    endpoint: str,
    title: str,
) -> str:
    raw = f"{category}|{method.upper()}|{endpoint}|{title}"
    digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:8].upper()
    return f"{prefix}-{digest}"


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