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

PROMPT_INJECTION_CONTROLS = {
    "allowlist_only_tools",
    "tool_description_sanitization",
    "server_instruction_sanitization",
    "tool_argument_validation",
    "resource_content_sanitization",
    "human_approval_for_writes",
}


def normalize_prompt_injection_controls(controls: Optional[List[str]]) -> Tuple[List[str], List[str]]:
    if not controls:
        return [], []

    normalized: List[str] = []
    unknown: List[str] = []
    seen = set()

    for control in controls:
        key = control.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        if key in PROMPT_INJECTION_CONTROLS:
            normalized.append(key)
        else:
            unknown.append(control)

    return normalized, unknown


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


def auth_posture_penalties(
    auth_required: Optional[bool], exposed_publicly: Optional[bool]
) -> Tuple[int, int, List[str]]:
    notes: List[str] = []

    if auth_required is False:
        auth_penalty = 18
        notes.append("No authentication required")
    elif auth_required is True:
        auth_penalty = 0
        notes.append("Authentication required")
    else:
        auth_penalty = 0
        notes.append("Authentication requirement not provided")

    exposure_penalty = 0
    if exposed_publicly is True:
        if auth_required is False:
            exposure_penalty = 12
            notes.append("Publicly exposed endpoint without authentication")
        elif auth_required is True:
            exposure_penalty = 4
            notes.append("Publicly exposed endpoint (authentication present)")
        else:
            exposure_penalty = 8
            notes.append("Publicly exposed endpoint with unknown authentication posture")
    elif exposed_publicly is False:
        notes.append("Not publicly exposed")
    else:
        notes.append("Public exposure posture not provided")

    return auth_penalty, exposure_penalty, notes


def prompt_injection_posture_adjustment(
    controls: Optional[List[str]], permission_label: str, exposed_publicly: Optional[bool]
) -> Tuple[int, str, List[str]]:
    notes: List[str] = []

    if controls is None:
        notes.append("Prompt-injection controls not provided")
        return 0, "unknown", notes

    normalized, unknown = normalize_prompt_injection_controls(controls)
    coverage = len(normalized)
    risk_surface = permission_label in {"medium", "high"} or exposed_publicly is True

    if risk_surface:
        if coverage >= 4:
            adjustment = 6
            label = "strong"
        elif coverage == 3:
            adjustment = 3
            label = "moderate"
        elif coverage == 2:
            adjustment = -2
            label = "partial"
        elif coverage == 1:
            adjustment = -8
            label = "weak"
        else:
            adjustment = -12
            label = "weak"
    else:
        if coverage >= 4:
            adjustment = 5
            label = "strong"
        elif coverage >= 2:
            adjustment = 3
            label = "moderate"
        elif coverage == 1:
            adjustment = 1
            label = "partial"
        else:
            adjustment = 0
            label = "none"

    if coverage:
        notes.append(f"Prompt-injection controls declared: {', '.join(sorted(normalized))}")
    else:
        notes.append("No prompt-injection controls declared")

    if unknown:
        notes.append(f"Unrecognized controls ignored: {', '.join(sorted(str(item) for item in unknown))}")

    if risk_surface and coverage < 3:
        notes.append("High-risk/public server should declare at least 3 prompt-injection controls")

    return adjustment, label, notes


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
    auth_penalty, exposure_penalty, auth_notes = auth_posture_penalties(
        server.auth_required, server.exposed_publicly
    )
    injection_adjustment, injection_label, injection_notes = prompt_injection_posture_adjustment(
        server.prompt_injection_controls, permission_label, server.exposed_publicly
    )

    permission_penalty = int(round(permission_score * 2))  # 0..40
    stale = stale_penalty(server.last_commit_days_ago)
    issues = issue_penalty(server.stars, server.open_issues)
    popularity = min(10, int(server.stars / 25))
    license_adjustment = 5 if server.license else -10
    maintainer_bonus = min(8, max(0, server.maintainers * 2))

    score = 100
    score -= permission_penalty
    score -= auth_penalty
    score -= exposure_penalty
    score -= stale
    score -= issues
    score += popularity
    score += license_adjustment
    score += maintainer_bonus
    score += injection_adjustment
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
        auth_penalty=auth_penalty,
        exposure_penalty=exposure_penalty,
        auth_notes=auth_notes,
        injection_adjustment=injection_adjustment,
        injection_label=injection_label,
        injection_notes=injection_notes,
    )

    return TrustScore(name=server.name, score=score, tier=tier_for(score), breakdown=breakdown)


def score_all(servers: List[Server]) -> List[TrustScore]:
    return sorted((score_server(s) for s in servers), key=lambda x: x.score, reverse=True)
