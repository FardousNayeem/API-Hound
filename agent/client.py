"""
HTTP client wrapper around httpx.
- Returns a normalized APIResponse object on every call
- Logs every request/response to agent_log.txt
- Redacts Authorization header values in logs
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

from agent.config import TIMEOUT, LOG_PATH


# Normalized Response
class APIResponse:
    def __init__(
        self,
        status_code: int,
        headers: Dict[str, str],
        body: Any,
        raw_text: str,
        elapsed_ms: float,
        request_info: Dict[str, Any],
    ):
        self.status_code  = status_code
        self.headers      = headers          # lower-cased keys
        self.body         = body             # parsed JSON or None
        self.raw_text     = raw_text
        self.elapsed_ms   = elapsed_ms
        self.request_info = request_info     # for evidence blocks

    def to_evidence_response(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers":     dict(self.headers),
            "body":        self.body if self.body is not None else self.raw_text,
            "elapsed_ms":  round(self.elapsed_ms, 2),
        }


# Client
class APIClient:
    def __init__(self, base_url: str, log_path: Path = LOG_PATH):
        self.base_url   = base_url.rstrip("/")
        self.log_path   = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_file  = open(self.log_path, "a", encoding="utf-8")
        self._req_count = 0

    # Core request
    def request(
        self,
        method: str,
        path: str,
        *,
        token: Optional[str] = None,
        json_body: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        content_type: str = "application/json",
    ) -> APIResponse:
        url = self.base_url + path
        req_headers: Dict[str, str] = {"Content-Type": content_type}

        if token:
            req_headers["Authorization"] = f"Bearer {token}"
        if headers:
            req_headers.update(headers)

        self._req_count += 1
        request_info = {
            "method":  method.upper(),
            "url":     url,
            "headers": self._redact_headers(req_headers),
            "body":    json_body,
            "params":  params,
        }

        start = time.perf_counter()
        try:
            with httpx.Client(timeout=TIMEOUT) as client:
                response = client.request(
                    method,
                    url,
                    json=json_body,
                    params=params,
                    headers=req_headers,
                )
        except httpx.TimeoutException:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._log_entry(request_info, None, elapsed_ms, error="TIMEOUT")
            return APIResponse(
                status_code=0,
                headers={},
                body=None,
                raw_text="",
                elapsed_ms=elapsed_ms,
                request_info=request_info,
            )
        except Exception as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self._log_entry(request_info, None, elapsed_ms, error=str(exc))
            return APIResponse(
                status_code=0,
                headers={},
                body=None,
                raw_text="",
                elapsed_ms=elapsed_ms,
                request_info=request_info,
            )

        elapsed_ms = (time.perf_counter() - start) * 1000

        # Parse body
        raw_text = response.text
        try:
            body = response.json()
        except Exception:
            body = None

        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        response_info = {
            "status_code": response.status_code,
            "headers":     dict(resp_headers),
            "body":        body if body is not None else raw_text,
            "elapsed_ms":  round(elapsed_ms, 2),
        }

        self._log_entry(request_info, response_info, elapsed_ms)

        return APIResponse(
            status_code=response.status_code,
            headers=resp_headers,
            body=body,
            raw_text=raw_text,
            elapsed_ms=elapsed_ms,
            request_info=request_info,
        )

    # Convenience methods
    def get(self, path: str, **kwargs) -> APIResponse:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs) -> APIResponse:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs) -> APIResponse:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs) -> APIResponse:
        return self.request("DELETE", path, **kwargs)

    def options(self, path: str, **kwargs) -> APIResponse:
        return self.request("OPTIONS", path, **kwargs)

    def head(self, path: str, **kwargs) -> APIResponse:
        return self.request("HEAD", path, **kwargs)

    # Logging
    def _redact_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        redacted = {}
        for k, v in headers.items():
            if k.lower() == "authorization":
                redacted[k] = "Bearer [REDACTED]"
            else:
                redacted[k] = v
        return redacted

    def _log_entry(
        self,
        request_info: Dict[str, Any],
        response_info: Optional[Dict[str, Any]],
        elapsed_ms: float,
        error: Optional[str] = None,
    ):
        sep = "─" * 72
        lines = [
            f"\n{sep}",
            f"REQUEST #{self._req_count}",
            f"  {request_info['method']} {request_info['url']}",
            f"  Params:  {json.dumps(request_info.get('params'))}",
            f"  Headers: {json.dumps(request_info.get('headers'))}",
            f"  Body:    {json.dumps(request_info.get('body'))}",
        ]
        if error:
            lines.append(f"  ERROR:   {error}  ({elapsed_ms:.0f}ms)")
        elif response_info:
            lines += [
                f"RESPONSE",
                f"  Status:  {response_info['status_code']}  ({elapsed_ms:.0f}ms)",
                f"  Headers: {json.dumps(response_info.get('headers'))}",
                f"  Body:    {json.dumps(response_info.get('body'))[:500]}",
            ]
        self._log_file.write("\n".join(lines) + "\n")
        self._log_file.flush()

    def close(self):
        self._log_file.close()

    @property
    def request_count(self) -> int:
        return self._req_count
