"""
Central configuration: base URL, credentials, timeouts, paths, endpoint registry.
CLI args override .env, which overrides defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()


BASE_DIR = Path(__file__).resolve().parent.parent

OPENAPI_PATH  = BASE_DIR / os.getenv("OPENAPI_PATH",  "resources/openapi.json")
SCHEMA_PATH   = BASE_DIR / os.getenv("SCHEMA_PATH",   "resources/report.schema.json")
OUTPUT_PATH   = BASE_DIR / os.getenv("OUTPUT_PATH",   "output/report.json")
LOG_PATH      = BASE_DIR / os.getenv("LOG_PATH",      "output/agent_log.txt")

# API

BASE_URL: str = os.getenv("BASE_URL", "https://backend-agent-test.onrender.com")

TIMEOUT: float = 15.0        # seconds per request
BURST_COUNT: int = 15        # requests used in rate-limit burst test
PERF_THRESHOLD_MS: float = 2000.0   # flag responses slower than this

AGENT_NAME    = "backend-testing-agent-v1"
SPEC_VERSION  = "1.0.0"

# Credentials
CREDENTIALS = {
    "alice": {
        "username": os.getenv("ALICE_USERNAME", "alice"),
        "password": os.getenv("ALICE_PASSWORD", "alice123"),
    },
    "bob": {
        "username": os.getenv("BOB_USERNAME", "bob"),
        "password": os.getenv("BOB_PASSWORD", "bob123"),
    },
    "carol": {
        "username": os.getenv("CAROL_USERNAME", "carol"),
        "password": os.getenv("CAROL_PASSWORD", "carol123"),
    },
}

# Endpoint Registry (method, path_template, auth_required, expected_success_code)
ENDPOINTS = [
    # auth
    ("POST",   "/auth/register",                  False, 201),
    ("POST",   "/auth/login",                     False, 200),
    ("POST",   "/auth/logout",                    True,  200),
    # users
    ("GET",    "/users/me",                       True,  200),
    ("PATCH",  "/users/me",                       True,  200),
    ("GET",    "/users/{user_id}",                False, 200),
    # posts
    ("GET",    "/posts",                          False, 200),
    ("POST",   "/posts",                          True,  201),
    ("GET",    "/posts/{post_id}",                False, 200),
    ("PATCH",  "/posts/{post_id}",                True,  200),
    ("DELETE", "/posts/{post_id}",                True,  200),
    # comments
    ("GET",    "/posts/{post_id}/comments",       False, 200),
    ("POST",   "/posts/{post_id}/comments",       True,  201),
    # likes
    ("POST",   "/posts/{post_id}/like",           True,  200),
    ("DELETE", "/posts/{post_id}/like",           True,  200),
    # follows
    ("POST",   "/users/{user_id}/follow",         True,  200),
    ("DELETE", "/users/{user_id}/follow",         True,  200),
    # meta
    ("GET",    "/",                               False, 200),
]

TOTAL_ENDPOINTS = len(ENDPOINTS)

# Probe Paths (endpoint_existence.py)
PROBE_PATHS = [
    "/docs",
    "/redoc",
    "/openapi.json",
    "/admin",
    "/debug",
    "/metrics",
    "/health",
    "/users",
    "/status",
]

# Security Headers check
EXPECTED_SECURITY_HEADERS = [
    "x-content-type-options",
    "x-frame-options",
    "strict-transport-security",
]
