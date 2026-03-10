from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import List, Optional

from .github_client import fetch_repo_metadata
from .models import Server, parse_servers
from .report import to_dict, to_markdown
from .scoring import score_all


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Score MCP servers by trust and maintenance signals.")
    sub = parser.add_subparsers(dest="command", required=True)

    cmd = sub.add_parser("score", help="Generate trust scores")
    cmd.add_argument("--input", required=True, help="Path to servers JSON")
    cmd.add_argument("--output", help="Write JSON report")
    cmd.add_argument("--markdown", help="Write markdown report")
    cmd.add_argument("--live", action="store_true", help="Fetch GitHub metadata for repos")

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

        # Return non-zero if any server is in caution tier
        return 1 if any(s.tier == "caution" for s in scores) else 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
