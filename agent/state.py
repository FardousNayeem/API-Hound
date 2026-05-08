from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from agent.auth import AuthTokens
from agent.models.report import Finding


@dataclass
class SessionState:
    # Auth
    tokens: AuthTokens = field(default_factory=AuthTokens)

    # Discovered user IDs (from /users/me responses)
    user_ids: Dict[str, int] = field(default_factory=dict)

    # Posts created during the test run
    created_post_ids: Dict[str, int] = field(default_factory=dict)

    # Posts discovered from the public feed
    discovered_post_ids: List[int] = field(default_factory=list)

    # Comments created during the run
    created_comment_ids: List[int] = field(default_factory=list)

    # Findings collected across all checks
    findings: List[Finding] = field(default_factory=list)

    # Metrics
    endpoints_tested: int = 0

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        print(f"  [finding] [{finding.severity.upper()}] {finding.title}")

    def alice_token(self) -> Optional[str]:
        return self.tokens.alice

    def bob_token(self) -> Optional[str]:
        return self.tokens.bob

    def carol_token(self) -> Optional[str]:
        return self.tokens.carol
