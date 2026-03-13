from __future__ import annotations

from typing import List

from .models import TrustScore


def to_dict(scores: List[TrustScore]) -> dict:
    return {
        "servers": [
            {
                "name": s.name,
                "score": s.score,
                "tier": s.tier,
                "breakdown": {
                    "permission_risk": s.breakdown.permission_risk,
                    "permission_label": s.breakdown.permission_label,
                    "permission_notes": s.breakdown.permission_notes,
                    "auth_penalty": s.breakdown.auth_penalty,
                    "exposure_penalty": s.breakdown.exposure_penalty,
                    "auth_notes": s.breakdown.auth_notes,
                    "stale_penalty": s.breakdown.stale_penalty,
                    "issue_penalty": s.breakdown.issue_penalty,
                    "popularity_bonus": s.breakdown.popularity_bonus,
                    "license_adjustment": s.breakdown.license_adjustment,
                    "maintainer_bonus": s.breakdown.maintainer_bonus,
                },
            }
            for s in scores
        ]
    }


def to_markdown(scores: List[TrustScore]) -> str:
    lines = [
        "# MCP Trust Radar Report",
        "",
        "| Server | Score | Tier | Permission Risk |",
        "|---|---:|---|---|",
    ]
    for s in scores:
        lines.append(
            f"| {s.name} | {s.score} | {s.tier} | {s.breakdown.permission_label} ({s.breakdown.permission_risk}) |"
        )

    lines.append("")
    lines.append("## Notes")
    for s in scores:
        lines.append("")
        lines.append(f"### {s.name}")
        for n in s.breakdown.permission_notes:
            lines.append(f"- {n}")
        for n in s.breakdown.auth_notes:
            lines.append(f"- {n}")
        lines.append(f"- Auth penalty: {s.breakdown.auth_penalty}")
        lines.append(f"- Exposure penalty: {s.breakdown.exposure_penalty}")
        lines.append(f"- Stale penalty: {s.breakdown.stale_penalty}")
        lines.append(f"- Issue penalty: {s.breakdown.issue_penalty}")
        lines.append(f"- Popularity bonus: +{s.breakdown.popularity_bonus}")
        lines.append(f"- License adjustment: {s.breakdown.license_adjustment:+d}")
        lines.append(f"- Maintainer bonus: +{s.breakdown.maintainer_bonus}")

    return "\n".join(lines)
