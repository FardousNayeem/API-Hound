from __future__ import annotations
from typing import List
from agent.client import APIClient
from agent.state import SessionState
from agent.models.report import Finding

def run(client: APIClient, state: SessionState) -> List[Finding]:
    findings: List[Finding] = []
    # TODO: implement
    return findings