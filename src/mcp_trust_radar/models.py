from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Server:
    name: str
    repo: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    stars: int = 0
    open_issues: int = 0
    last_commit_days_ago: Optional[int] = None
    license: Optional[str] = None
    maintainers: int = 1


@dataclass
class RiskBreakdown:
    permission_risk: float
    permission_label: str
    permission_notes: List[str]
    stale_penalty: int
    issue_penalty: int
    popularity_bonus: int
    license_adjustment: int
    maintainer_bonus: int


@dataclass
class TrustScore:
    name: str
    score: int
    tier: str
    breakdown: RiskBreakdown


def parse_servers(data: Any) -> List[Server]:
    payload = data.get("servers", data)
    if not isinstance(payload, list):
        raise ValueError("Input must be a list or an object with a 'servers' list")

    servers: List[Server] = []
    for raw in payload:
        servers.append(
            Server(
                name=str(raw["name"]),
                repo=(str(raw["repo"]) if raw.get("repo") else None),
                permissions=[str(p) for p in (raw.get("permissions") or [])],
                stars=int(raw.get("stars", 0) or 0),
                open_issues=int(raw.get("open_issues", 0) or 0),
                last_commit_days_ago=(
                    int(raw["last_commit_days_ago"])
                    if raw.get("last_commit_days_ago") is not None
                    else None
                ),
                license=(str(raw["license"]) if raw.get("license") else None),
                maintainers=int(raw.get("maintainers", 1) or 1),
            )
        )

    return servers
