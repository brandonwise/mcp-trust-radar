from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .github_client import fetch_repo_metadata
from .models import Server, TrustScore, parse_servers
from .report import to_dict, to_markdown
from .scoring import normalize_prompt_injection_controls, permission_risk, score_all

TIER_RANK = {
    "caution": 0,
    "review": 1,
    "trusted": 2,
}

POLICY_PRESETS: Dict[str, Dict[str, object]] = {
    "balanced": {
        "minimum_tier": "review",
        "minimum_score": None,
        "block_public_without_auth": False,
        "minimum_public_controls": None,
        "minimum_risk_surface_controls": None,
    },
    "internet-facing": {
        "minimum_tier": "review",
        "minimum_score": 60,
        "block_public_without_auth": True,
        "minimum_public_controls": 3,
        "minimum_risk_surface_controls": 2,
    },
    "strict": {
        "minimum_tier": "trusted",
        "minimum_score": 75,
        "block_public_without_auth": True,
        "minimum_public_controls": 4,
        "minimum_risk_surface_controls": 3,
    },
}


def resolve_policy_settings(args: argparse.Namespace) -> Dict[str, object]:
    preset = POLICY_PRESETS[args.policy]

    minimum_tier = args.minimum_tier or preset["minimum_tier"]
    minimum_score = args.minimum_score if args.minimum_score is not None else preset["minimum_score"]
    minimum_public_controls = (
        args.minimum_public_controls
        if args.minimum_public_controls is not None
        else preset["minimum_public_controls"]
    )
    minimum_risk_surface_controls = (
        args.minimum_risk_surface_controls
        if args.minimum_risk_surface_controls is not None
        else preset["minimum_risk_surface_controls"]
    )

    return {
        "minimum_tier": minimum_tier,
        "minimum_score": minimum_score,
        "block_public_without_auth": args.block_public_without_auth
        or bool(preset["block_public_without_auth"]),
        "minimum_public_controls": minimum_public_controls,
        "minimum_risk_surface_controls": minimum_risk_surface_controls,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Score MCP servers by trust and maintenance signals.")
    sub = parser.add_subparsers(dest="command", required=True)

    cmd = sub.add_parser("score", help="Generate trust scores")
    cmd.add_argument("--input", required=True, help="Path to servers JSON")
    cmd.add_argument("--output", help="Write JSON report")
    cmd.add_argument("--markdown", help="Write markdown report")
    cmd.add_argument("--live", action="store_true", help="Fetch GitHub metadata for repos")
    cmd.add_argument(
        "--policy",
        choices=sorted(POLICY_PRESETS.keys()),
        default="balanced",
        help=(
            "Named gate policy preset. Use --minimum-* flags to override individual thresholds "
            "(default: balanced)."
        ),
    )
    cmd.add_argument(
        "--minimum-tier",
        choices=["caution", "review", "trusted"],
        help=(
            "Fail when any server falls below this tier. "
            "Defaults to policy preset (balanced=review, strict=trusted)."
        ),
    )
    cmd.add_argument(
        "--minimum-score",
        type=int,
        help="Fail when any server score is below this value (0-100).",
    )
    cmd.add_argument(
        "--block-public-without-auth",
        action="store_true",
        help="Fail when any publicly exposed server does not explicitly require authentication.",
    )
    cmd.add_argument(
        "--minimum-public-controls",
        type=int,
        help="Fail when any publicly exposed server has fewer than N recognized prompt-injection controls (0-6).",
    )
    cmd.add_argument(
        "--minimum-risk-surface-controls",
        type=int,
        help=(
            "Fail when any medium/high-risk or publicly exposed server has fewer than "
            "N recognized prompt-injection controls (0-6)."
        ),
    )

    return parser


def hydrate_live(servers: List[Server]) -> None:
    token = os.getenv("GITHUB_TOKEN")
    for s in servers:
        if not s.repo:
            continue
        data = fetch_repo_metadata(s.repo, token=token)
        s.stars = data["stars"]
        s.open_issues = data["open_issues"]
        s.license = data["license"]
        s.last_commit_days_ago = data["last_commit_days_ago"]


def evaluate_gate(
    scores: Sequence[TrustScore],
    minimum_tier: str = "review",
    minimum_score: Optional[int] = None,
    *,
    servers: Optional[Sequence[Server]] = None,
    block_public_without_auth: bool = False,
    minimum_public_controls: Optional[int] = None,
    minimum_risk_surface_controls: Optional[int] = None,
) -> Tuple[bool, List[str]]:
    if minimum_tier not in TIER_RANK:
        raise ValueError(f"Unknown tier: {minimum_tier}")

    if minimum_score is not None and not (0 <= minimum_score <= 100):
        raise ValueError("--minimum-score must be between 0 and 100")

    if minimum_public_controls is not None and not (0 <= minimum_public_controls <= 6):
        raise ValueError("--minimum-public-controls must be between 0 and 6")

    if minimum_risk_surface_controls is not None and not (0 <= minimum_risk_surface_controls <= 6):
        raise ValueError("--minimum-risk-surface-controls must be between 0 and 6")

    reasons: List[str] = []

    min_rank = TIER_RANK[minimum_tier]
    below_tier = [s for s in scores if TIER_RANK[s.tier] < min_rank]
    if below_tier:
        examples = ", ".join(f"{s.name}({s.tier}/{s.score})" for s in below_tier[:3])
        if len(below_tier) > 3:
            examples += ", ..."
        reasons.append(
            f"{len(below_tier)} server(s) fell below minimum tier '{minimum_tier}': {examples}"
        )

    if minimum_score is not None:
        below_score = [s for s in scores if s.score < minimum_score]
        if below_score:
            examples = ", ".join(f"{s.name}({s.score})" for s in below_score[:3])
            if len(below_score) > 3:
                examples += ", ..."
            reasons.append(
                f"{len(below_score)} server(s) scored below minimum score {minimum_score}: {examples}"
            )

    if (
        block_public_without_auth
        or minimum_public_controls is not None
        or minimum_risk_surface_controls is not None
    ):
        if servers is None:
            raise ValueError("servers are required for public posture policy checks")

        public_servers = [server for server in servers if server.exposed_publicly is True]

        if block_public_without_auth:
            offenders = [server for server in public_servers if server.auth_required is not True]
            if offenders:
                examples = ", ".join(server.name for server in offenders[:3])
                if len(offenders) > 3:
                    examples += ", ..."
                reasons.append(
                    f"{len(offenders)} publicly exposed server(s) missing explicit auth_required=true: {examples}"
                )

        if minimum_public_controls is not None:
            weak_public = []
            for server in public_servers:
                normalized, _ = normalize_prompt_injection_controls(server.prompt_injection_controls)
                if len(normalized) < minimum_public_controls:
                    weak_public.append((server.name, len(normalized)))

            if weak_public:
                examples = ", ".join(
                    f"{name}({count})" for name, count in weak_public[:3]
                )
                if len(weak_public) > 3:
                    examples += ", ..."
                reasons.append(
                    f"{len(weak_public)} publicly exposed server(s) declared fewer than {minimum_public_controls} prompt-injection controls: {examples}"
                )

        if minimum_risk_surface_controls is not None:
            weak_risk_surface = []
            for server in servers:
                _, permission_label, _ = permission_risk(server.permissions)
                risk_surface = server.exposed_publicly is True or permission_label in {"medium", "high"}
                if not risk_surface:
                    continue

                normalized, _ = normalize_prompt_injection_controls(server.prompt_injection_controls)
                if len(normalized) < minimum_risk_surface_controls:
                    posture = "public" if server.exposed_publicly is True else f"{permission_label}-risk permissions"
                    weak_risk_surface.append((server.name, len(normalized), posture))

            if weak_risk_surface:
                examples = ", ".join(
                    f"{name}({count}; {posture})"
                    for name, count, posture in weak_risk_surface[:3]
                )
                if len(weak_risk_surface) > 3:
                    examples += ", ..."
                reasons.append(
                    f"{len(weak_risk_surface)} risk-surface server(s) declared fewer than {minimum_risk_surface_controls} prompt-injection controls: {examples}"
                )

    return len(reasons) == 0, reasons


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "score":
        raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
        servers = parse_servers(raw)

        if args.live:
            hydrate_live(servers)

        scores = score_all(servers)
        payload = to_dict(scores)
        print(json.dumps(payload, indent=2))

        if args.output:
            Path(args.output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        if args.markdown:
            Path(args.markdown).write_text(to_markdown(scores), encoding="utf-8")

        policy_settings = resolve_policy_settings(args)

        passed, reasons = evaluate_gate(
            scores,
            minimum_tier=str(policy_settings["minimum_tier"]),
            minimum_score=policy_settings["minimum_score"],
            servers=servers,
            block_public_without_auth=bool(policy_settings["block_public_without_auth"]),
            minimum_public_controls=policy_settings["minimum_public_controls"],
            minimum_risk_surface_controls=policy_settings["minimum_risk_surface_controls"],
        )
        if not passed:
            for reason in reasons:
                print(f"GATE FAIL: {reason}", file=sys.stderr)
            return 1

        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
