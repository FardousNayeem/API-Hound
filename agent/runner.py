from __future__ import annotations

import traceback
from typing import List

from agent.auth import login_all
from agent.client import APIClient
from agent.state import SessionState
from agent.spec import operation_count

from agent.checks import (
    authentication,
    authorization,
    business_logic,
    input_validation,
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
)

# Check execution order
CHECK_MODULES = [
    authentication,       # no-token / bad-token on all protected routes
    authorization,        # IDOR, cross-user mutations, privilege escalation
    input_validation,     # boundary values, type errors, missing required fields
    business_logic,       # follow-self, double-like, ghost resources
    schema_contract,      # response shapes vs OpenAPI spec
    status_code,          # correct HTTP codes for success and error paths
    error_handling,       # stack traces, crash vectors, unicode edge cases
    headers_cors,         # security headers, CORS policy
    rate_limiting,        # burst tests on login and register
    http_protocol,        # OPTIONS, HEAD, Accept negotiation, trailing slash
    consistency,          # field naming, shape parity, null vs absent
    performance,          # response time, uncapped pagination, cache headers
    documentation_drift,  # spec vs reality divergence
    endpoint_existence,   # all documented routes exist, undocumented probes
]


def run(client: APIClient, base_url: str, openapi_spec: dict) -> SessionState:
    state = SessionState()
    print(f"\n[runner] Loaded OpenAPI spec with {operation_count(openapi_spec)} documented operation(s)")
        
    # 1: Reachability
    print("\n[runner] Checking API reachability...")
    if not _check_reachability(client):
        print("  [runner] ✗ API is not reachable. Check base URL and network.")
        return state
    print("  [runner] ✓ API is reachable")

    # 2: Authenticate
    print("\n[runner] Authenticating users...")
    state.tokens = login_all(client)

    valid = state.tokens.all_valid()
    if not valid:
        print("  [runner] ✗ All logins failed — cannot proceed.")
        return state
    print(f"  [runner] ✓ Authenticated: {list(valid.keys())}")

    # 3: Discover state
    print("\n[runner] Discovering live API state...")
    _discover_state(client, state)

    _print_state_summary(state)

    # 4: Run checks
    total = len(CHECK_MODULES)
    for i, module in enumerate(CHECK_MODULES, 1):
        name = module.__name__.split(".")[-1]
        print(f"\n[runner] [{i}/{total}] {name}")
        try:
            findings = module.run(client, state)
            for f in findings:
                state.add_finding(f)
            if not findings:
                print(f"  [runner] no findings")
        except Exception:
            tb = traceback.format_exc()
            print(f"  [runner] ERROR in {name}:\n{tb}")

    return state


# Reachability
def _check_reachability(client: APIClient) -> bool:
    try:
        resp = client.get("/")
        return resp.status_code != 0
    except Exception:
        return False


# State discovery
def _discover_state(client: APIClient, state: SessionState) -> None:
    """
    Populates:
      - state.user_ids       {"alice": 1, "bob": 2, ...}
      - state.created_post_ids {"alice": 42, "bob": 43, ...}
      - state.discovered_post_ids [1, 2, 3, ...]
    """

    for user, token in state.tokens.all_valid().items():
        resp = client.get("/users/me", token=token)
        state.endpoints_tested += 1
        if resp.status_code == 200 and isinstance(resp.body, dict):
            uid = resp.body.get("id")
            if uid is not None:
                state.user_ids[user] = int(uid)
                print(f"  [discover] {user} → user_id={uid}")
        else:
            print(f"  [discover] ✗ {user} /users/me → HTTP {resp.status_code}")

    resp = client.get("/posts", params={"limit": 10})
    state.endpoints_tested += 1
    if resp.status_code == 200 and isinstance(resp.body, list):
        for post in resp.body:
            if isinstance(post, dict):
                pid = post.get("id")
                if pid is not None:
                    state.discovered_post_ids.append(int(pid))
        print(f"  [discover] found {len(state.discovered_post_ids)} existing post(s) in feed")

    for user, token in state.tokens.all_valid().items():
        resp = client.post(
            "/posts",
            token=token,
            json_body={"body": f"Agent test post — {user}"},
        )
        state.endpoints_tested += 1

        if resp.status_code in (200, 201) and isinstance(resp.body, dict):
            pid = resp.body.get("id")
            if pid is not None:
                state.created_post_ids[user] = int(pid)
                print(f"  [discover] created post for {user} → post_id={pid}")
            else:
                print(f"  [discover] ✗ {user} post created but no id in response")
        else:
            print(f"  [discover] ✗ {user} post creation → HTTP {resp.status_code}: {str(resp.body)[:80]}")

        if user not in state.created_post_ids and state.discovered_post_ids:
            state.created_post_ids[user] = state.discovered_post_ids[0]
            print(f"  [discover] fallback: {user} using discovered post_id={state.discovered_post_ids[0]}")


def _print_state_summary(state: SessionState) -> None:
    print(f"\n  [state] user_ids       : {state.user_ids}")
    print(f"  [state] created_posts  : {state.created_post_ids}")
    print(f"  [state] discovered     : {state.discovered_post_ids[:5]}"
          f"{'...' if len(state.discovered_post_ids) > 5 else ''}")
    missing_tokens = [u for u in ("alice", "bob", "carol") if not state.tokens.get(u)]
    if missing_tokens:
        print(f"  [state] ⚠ missing tokens: {missing_tokens}")
