from __future__ import annotations

import json
from pathlib import Path
from typing import Dict


Credentials = Dict[str, Dict[str, str]]


def load_credentials(path: Path) -> Credentials:
    if not path.exists():
        raise FileNotFoundError(f"Credentials file not found: {path}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        raise ValueError("Credentials file must contain a JSON object")

    required_users = ("alice", "bob", "carol")

    for user in required_users:
        if user not in data:
            raise ValueError(f"Missing credentials for user: {user}")

        user_creds = data[user]
        if not isinstance(user_creds, dict):
            raise ValueError(f"Credentials for {user} must be an object")

        username = user_creds.get("username")
        password = user_creds.get("password")

        if not isinstance(username, str) or not username:
            raise ValueError(f"Credentials for {user} must include non-empty username")

        if not isinstance(password, str) or not password:
            raise ValueError(f"Credentials for {user} must include non-empty password")

    return data