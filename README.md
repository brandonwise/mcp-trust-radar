# mcp-trust-radar

Quick trust scoring for MCP servers.

`mcp-trust-radar` helps you answer a practical question before enabling any server:

> Should this server run in my environment right now?

It scores servers using permission risk, repo freshness, issue pressure, maintainer depth, and license posture.

## Why this matters

MCP tooling is moving fast. Discovery is getting easier, but trust decisions are still mostly manual.

This project gives you a repeatable first-pass filter so you can:

- Spot obvious high-risk servers early
- Rank candidates before deeper security review
- Keep trust checks consistent across teams

## What it scores

- Permission risk (read-only vs shell/write/network capabilities)
- Maintenance health (how stale the repo is)
- Issue pressure (open issues relative to repo traction)
- License signal (clear SPDX vs missing)
- Maintainer depth (single maintainer vs shared ownership)

## Install

```bash
pip install -e .
```

## Quick start

```bash
mcp-radar score \
  --input examples/servers.json \
  --output trust-report.json \
  --markdown trust-report.md
```

The command exits with non-zero when any server lands in `caution` tier (useful for CI policies).

## Optional live GitHub enrichment

If `repo` is present in your input, you can pull fresh metadata:

```bash
export GITHUB_TOKEN=... # optional but recommended for rate limits
mcp-radar score --input examples/servers.json --live
```

## Tiers

- `trusted` (75–100): generally safe to trial with normal controls
- `review` (55–74): usable, but needs manual review first
- `caution` (0–54): high-risk or poorly maintained; block by default

## Repo layout

- `src/mcp_trust_radar/`: scoring engine + CLI
- `examples/`: sample input for quick testing
- `tests/`: unit tests

## Development

```bash
pip install -e . pytest
pytest
```

## License

MIT
