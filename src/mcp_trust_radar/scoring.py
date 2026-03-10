from __future__ import annotations

from typing import List, Optional, Tuple

from .models import RiskBreakdown, Server, TrustScore

HIGH_RISK_KEYWORDS = (
    "write",
    "delete",
    "exec",
    "shell",
    "spawn",
    "system",
    "network",
    "http",
    "fetch",
    "command",
)

MEDIUM_RISK_KEYWORDS = (
    "update",
    "create",
    "post",
    "patch",
    "run",
)


def permission_risk(permissions: List[str]) -> Tuple[float, str, List[str]]:
    risk = 0.0
    notes: List[str] = []

    for perm in permissions:
        p = perm.lower()
        if any(k in p for k in HIGH_RISK_KEYWORDS):
            risk += 3.0
            notes.append(f"High-risk capability detected: {perm}")
        elif any(k in p for k in MEDIUM_RISK_KEYWORDS):
            risk += 1.5
            notes.append(f"Medium-risk capability detected: {perm}")

    risk = min(risk, 20.0)
    if risk <= 5:
        label = "low"
    elif risk <= 12:
        label = "medium"
    else:
        label = "high"

    if not notes:
        notes.append("No risky permission patterns detected")

    return risk, label, notes


def stale_penalty(days_since_commit: Optional[int]) -> int:
    if days_since_commit is None:
        return 8
    if days_since_commit <= 30:
        return 0
    if days_since_commit <= 90:
        return 3
    if days_since_commit <= 180:
        return 7
    if days_since_commit <= 365:
        return 12
    return 20


def issue_penalty(stars: int, open_issues: int) -> int:
    if open_issues <= 0:
        return 0
    baseline = max(stars, 20)
    ratio = open_issues / baseline
    return min(15, int(round(ratio * 25)))


def tier_for(score: int) -> str:
    if score >= 75:
        return "trusted"
    if score >= 55:
        return "review"
    return "caution"


def score_server(server: Server) -> TrustScore:
    permission_score, permission_label, permission_notes = permission_risk(server.permissions)

    permission_penalty = int(round(permission_score * 2))  # 0..40
    stale = stale_penalty(server.last_commit_days_ago)
    issues = issue_penalty(server.stars, server.open_issues)
    popularity = min(10, int(server.stars / 25))
    license_adjustment = 5 if server.license else -10
    maintainer_bonus = min(8, max(0, server.maintainers * 2))

    score = 100
    score -= permission_penalty
    score -= stale
    score -= issues
    score += popularity
    score += license_adjustment
    score += maintainer_bonus
    score = max(0, min(score, 100))

    breakdown = RiskBreakdown(
        permission_risk=round(permission_score, 2),
        permission_label=permission_label,
        permission_notes=permission_notes,
        stale_penalty=stale,
        issue_penalty=issues,
        popularity_bonus=popularity,
        license_adjustment=license_adjustment,
        maintainer_bonus=maintainer_bonus,
    )

    return TrustScore(name=server.name, score=score, tier=tier_for(score), breakdown=breakdown)


def score_all(servers: List[Server]) -> List[TrustScore]:
    return sorted((score_server(s) for s in servers), key=lambda x: x.score, reverse=True)
