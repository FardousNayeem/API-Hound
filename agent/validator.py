from __future__ import annotations

import json
from pathlib import Path
from typing import Tuple, List

import jsonschema
from jsonschema import Draft202012Validator


def load_schema(schema_path: Path) -> dict:
    with open(schema_path, encoding="utf-8") as f:
        return json.load(f)


def validate_report(report_dict: dict, schema_path: Path) -> Tuple[bool, List[str]]:
    """
    Returns (is_valid, list_of_error_messages).
    """
    schema = load_schema(schema_path)
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(report_dict), key=lambda e: list(e.path))

    if not errors:
        return True, []

    messages = []
    for err in errors:
        path = " → ".join(str(p) for p in err.absolute_path) or "(root)"
        messages.append(f"  {path}: {err.message}")

    return False, messages


def validate_and_print(report_dict: dict, schema_path: Path) -> bool:
    is_valid, errors = validate_report(report_dict, schema_path)
    if is_valid:
        print("  Passed! report.json is valid against schema")
    else:
        print("  Failed! report.json FAILED schema validation. Following errors:")
        for e in errors:
            print(e)
    return is_valid
