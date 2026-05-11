import json
import time
import httpx
from pathlib import Path
from typing import Any, Dict, Optional

from agent.config import TIMEOUT, LOG_PATH
from agent.utils import redact


# Response
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
        self.body         = body             # parsed JSON
        self.raw_text     = raw_text
        self.elapsed_ms   = elapsed_ms
        self.request_info = request_info

    def to_evidence_response(self) -> Dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": redact(dict(self.headers)),
            "body": redact(self.body if self.body is not None else self.raw_text),
            "elapsed_ms": round(self.elapsed_ms, 2),
        }


# Client
class APIClient:
    def __init__(self, base_url: str, log_path: Path = LOG_PATH):
        self.base_url   = base_url.rstrip("/")
        self.log_path   = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_file  = open(self.log_path, "a", encoding="utf-8")
        self._req_count = 0

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
            "body":    redact(json_body),
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
            "headers": redact(dict(resp_headers)),
            "body": redact(body if body is not None else raw_text),
            "elapsed_ms": round(elapsed_ms, 2),
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
        return redact(headers)

    def _safe_json_preview(self, value: Any, max_chars: int = 1200) -> str:
        safe_value = redact(value)

        try:
            text = json.dumps(safe_value, ensure_ascii=False)
        except TypeError:
            text = str(safe_value)

        if len(text) > max_chars:
            return text[:max_chars] + "... [truncated]"

        return text


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
            f"  Params:  {self._safe_json_preview(request_info.get('params'))}",
            f"  Headers: {self._safe_json_preview(request_info.get('headers'))}",
            f"  Body:    {self._safe_json_preview(request_info.get('body'))}",
        ]

        if error:
            lines.append(f"  ERROR:   {error}  ({elapsed_ms:.0f}ms)")
        elif response_info:
            lines += [
                "RESPONSE",
                f"  Status:  {response_info['status_code']}  ({elapsed_ms:.0f}ms)",
                f"  Headers: {self._safe_json_preview(response_info.get('headers'))}",
                f"  Body:    {self._safe_json_preview(response_info.get('body'))}",
            ]

        self._log_file.write("\n".join(lines) + "\n")
        self._log_file.flush()

    def close(self):
        self._log_file.close()

    @property
    def request_count(self) -> int:
        return self._req_count
