"""
Backend Testing Agent package.

This package is a CLI-based black-box testing agent for the
Mini Social API. The public entry point is `agent.main`.

Main modules:
- main.py: CLI entry point
- runner.py: orchestrates authentication, discovery, checks, and reporting
- client.py: HTTP client wrapper with request/response logging
- auth.py: seeded-user authentication helpers
- state.py: typed session state shared across checks
- reporter.py: report.json builder
- validator.py: JSON Schema validator
"""

__version__ = "1.0.0"
__agent_name__ = "backend-testing-agent"

__all__ = [
    "__version__",
    "__agent_name__",
]