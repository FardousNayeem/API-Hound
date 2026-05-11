from __future__ import annotations
from typing import Dict, Optional
from agent.client import APIClient
import agent.config as config


INVALID_TOKEN  = "Bearer eyJhbGciOiJIUzI1NiJ9.invalid.payload"
MALFORMED_TOKEN = "notavalidtoken"
EXPIRED_TOKEN  = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwiZXhwIjoxfQ.expired"


class AuthTokens:
    def __init__(self):
        self.alice:  Optional[str] = None
        self.bob:    Optional[str] = None
        self.carol:  Optional[str] = None
        self.errors: Dict[str, str] = {}

    def get(self, user: str) -> Optional[str]:
        return getattr(self, user, None)

    def all_valid(self) -> Dict[str, str]:
        """Return dict of user → token for all successfully authenticated users."""
        result = {}
        for user in ("alice", "bob", "carol"):
            token = self.get(user)
            if token:
                result[user] = token
        return result


def login_all(client: APIClient) -> AuthTokens:
    """
    Attempt login for all three seeded users.
    Stores tokens in AuthTokens. Records failures in errors dict.
    """
    tokens = AuthTokens()

    for user, creds in config.CREDENTIALS.items():
        resp = client.post(
            "/auth/login",
            json_body={"username": creds["username"], "password": creds["password"]},
        )
        if resp.status_code == 200 and isinstance(resp.body, dict):
            token = resp.body.get("access_token")
            if token:
                setattr(tokens, user, token)
                print(f"  [auth] ✓ {user} logged in")
            else:
                tokens.errors[user] = "No access_token in response"
                print(f"  [auth] ✗ {user}: no access_token in response")
        else:
            tokens.errors[user] = f"HTTP {resp.status_code}: {resp.raw_text[:100]}"
            print(f"  [auth] ✗ {user}: HTTP {resp.status_code}")

    return tokens
