from __future__ import annotations

from agent.auth import login_all
from agent.client import APIClient
from agent.state import SessionState

from agent.checks import (
    authentication,
    authorization,
    business_logic,
    input_validation,
    schema_contract,
    status_code,
    headers_cors,
    rate_limiting,
    http_protocol,
    error_handling,
    consistency,
    performance,
    documentation_drift,
    endpoint_existence,
)

# Ordered list: deep/high-value checks first
CHECK_MODULES = [
    authentication,
    authorization,
    input_validation,
    business_logic,
    schema_contract,
    status_code,
    error_handling,
    headers_cors,
    rate_limiting,
    http_protocol,
    consistency,
    performance,
    documentation_drift,
    endpoint_existence,
]


def run(client: APIClient, base_url: str) -> SessionState:
    state = SessionState()

    # Authenticate
    print("\n[runner] Authenticating users...")
    state.tokens = login_all(client)

    # Discover state
    print("\n[runner] Discovering API state...")
    _discover_state(client, state)

    # Run checks
    for module in CHECK_MODULES:
        name = module.__name__.split(".")[-1]
        print(f"\n[runner] Running check: {name}")
        try:
            findings = module.run(client, state)
            for f in findings:
                state.add_finding(f)
        except Exception as exc:
            print(f"  [runner] ERROR in {name}: {exc}")

    return state


def _discover_state(client: APIClient, state: SessionState) -> None:
    """
    Resolve user IDs for alice/bob/carol, create one post each,
    and discover existing posts from the public feed.
    """
    # Resolve user IDs via /users/me
    for user, token in state.tokens.all_valid().items():
        resp = client.get("/users/me", token=token)
        if resp.status_code == 200 and isinstance(resp.body, dict):
            uid = resp.body.get("id")
            if uid is not None:
                state.user_ids[user] = uid
                print(f"  [discover] {user} → user_id={uid}")
        state.endpoints_tested += 1

    # Discover existing posts from public feed
    resp = client.get("/posts", params={"limit": 5})
    if resp.status_code == 200 and isinstance(resp.body, list):
        for post in resp.body:
            pid = post.get("id") if isinstance(post, dict) else None
            if pid:
                state.discovered_post_ids.append(pid)
        print(f"  [discover] Found {len(state.discovered_post_ids)} existing posts")
    state.endpoints_tested += 1

    # Create one post per authenticated user for authorization tests
    for user, token in state.tokens.all_valid().items():
        resp = client.post(
            "/posts",
            token=token,
            json_body={"body": f"Test post by {user} — agent run"},
        )
        if resp.status_code == 201 and isinstance(resp.body, dict):
            pid = resp.body.get("id")
            if pid:
                state.created_post_ids[user] = pid
                print(f"  [discover] Created post for {user} → post_id={pid}")
        state.endpoints_tested += 1
