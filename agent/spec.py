from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}

def load_openapi(path: Path) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def iter_operations(spec: Dict[str, Any]) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    for path, path_item in spec.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() in HTTP_METHODS and isinstance(operation, dict):
                yield method.upper(), path, operation

def first_success_code(operation: Dict[str, Any]) -> int | None:
    responses = operation.get("responses", {})
    for code in ("200", "201", "202", "204"):
        if code in responses:
            return int(code)
    return None

def spec_version(spec: Dict[str, Any]) -> str:
    return str(spec.get("info", {}).get("version", "unknown"))

def operation_count(spec: Dict[str, Any]) -> int:
    return sum(1 for _ in iter_operations(spec))