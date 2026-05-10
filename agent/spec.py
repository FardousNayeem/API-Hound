from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


def load_openapi(path: Path) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def iter_operations(spec: Dict[str, Any]) -> Iterable[Tuple[str, str, Dict[str, Any]]]:
    paths = spec.get("paths", {})

    if not isinstance(paths, dict):
        return

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue

            if not isinstance(operation, dict):
                continue

            yield method.upper(), path, operation

def operation_count(spec: Dict[str, Any]) -> int:
    return sum(1 for _ in iter_operations(spec))

def spec_version(spec: Dict[str, Any]) -> str:
    return str(spec.get("info", {}).get("version", "unknown"))

def api_title(spec: Dict[str, Any]) -> str:
    return str(spec.get("info", {}).get("title", "unknown"))

def first_success_code(operation: Dict[str, Any]) -> Optional[int]:
    responses = operation.get("responses", {})

    if not isinstance(responses, dict):
        return None

    for code in ("200", "201", "202", "204"):
        if code in responses:
            return int(code)

    return None

def expected_success_codes(spec: Dict[str, Any]) -> Dict[Tuple[str, str], int]:
    result: Dict[Tuple[str, str], int] = {}

    for method, path, operation in iter_operations(spec):
        code = first_success_code(operation)
        if code is not None:
            result[(method, path)] = code

    return result

def documented_operations(spec: Dict[str, Any]) -> list[tuple[str, str]]:
    return [(method, path) for method, path, _ in iter_operations(spec)]