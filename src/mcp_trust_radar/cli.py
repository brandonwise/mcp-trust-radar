from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from .github_client import fetch_repo_metadata
from .models import Server, TrustScore, parse_servers
from .report import to_dict, to_markdown
from .scoring import score_all

TIER_RANK = {
    "caution": 0,
    "review": 1,
    "trusted": 2,
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
        "--minimum-tier",
        choices=["caution", "review", "trusted"],
        default="review",
        help="Fail when any server falls below this tier (default: review, which blocks caution).",
    )
    cmd.add_argument(
        "--minimum-score",
        type=int,
        help="Fail when any server score is below this value (0-100).",
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
    scores: Sequence[TrustScore], minimum_tier: str = "review", minimum_score: Optional[int] = None
) -> Tuple[bool, List[str]]:
    if minimum_tier not in TIER_RANK:
        raise ValueError(f"Unknown tier: {minimum_tier}")

    if minimum_score is not None and not (0 <= minimum_score <= 100):
        raise ValueError("--minimum-score must be between 0 and 100")

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

        passed, reasons = evaluate_gate(
            scores,
            minimum_tier=args.minimum_tier,
            minimum_score=args.minimum_score,
        )
        if not passed:
            for reason in reasons:
                print(f"GATE FAIL: {reason}", file=sys.stderr)
            return 1

        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
