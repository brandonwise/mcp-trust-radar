# mcp-trust-radar

Quick trust scoring for MCP servers.

`mcp-trust-radar` helps you answer a practical question before enabling any server:

> Should this server run in my environment right now?

It scores servers using permission risk, authentication posture, public exposure risk, prompt-injection hardening signals, command-execution safeguards, repo freshness, issue pressure, maintainer depth, and license posture.

## Why this matters

MCP tooling is moving fast. Discovery is getting easier, but trust decisions are still mostly manual.

This project gives you a repeatable first-pass filter so you can:

- Spot obvious high-risk servers early
- Rank candidates before deeper security review
- Keep trust checks consistent across teams

## What it scores

- Permission risk (read-only vs shell/write/network capabilities)
- Authentication posture (`auth_required`)
- Public exposure posture (`exposed_publicly`)
- Prompt-injection hardening controls (`prompt_injection_controls`)
- Command-execution safeguard posture (allowlist + human approval controls for command-capable servers)
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

By default, the command exits non-zero when any server lands in `caution` tier (useful for CI policies).

You can tighten or loosen the release gate with policy flags:

- `--minimum-tier review` (default): fail only on `caution`
- `--minimum-tier trusted`: require every server to be `trusted`
- `--minimum-tier caution`: disable tier-based failures
- `--minimum-score N`: fail if any score is below `N`
- `--minimum-public-controls N`: fail if any public server declares fewer than N recognized controls
- `--minimum-risk-surface-controls N`: fail if any medium/high-risk or public server declares fewer than N recognized controls
- `--minimum-command-controls N`: fail if any command-capable server declares fewer than N recognized controls
- `--min-agent-trust N`: fail if attested agent trust score is below N
- `--max-attestation-age S`: fail if attestation is older than S seconds
- `--on-missing-attestation [ignore|warn|fail]`: behavior when attestation data is missing while attestation policy is configured (default: `warn`)

Examples:

```bash
# Strict policy: all servers must be trusted
mcp-radar score --input examples/servers.json --minimum-tier trusted

# Custom score bar: allow review tier, but block scores under 70
mcp-radar score --input examples/servers.json --minimum-tier review --minimum-score 70

# Block command-capable servers that don't declare at least 2 controls
mcp-radar score --input examples/servers.json --minimum-command-controls 2

# Require external agent trust score and fresh attestation
mcp-radar score \
  --input examples/servers.json \
  --agent-attestation examples/agent-attestation.json \
  --min-agent-trust 60 \
  --max-attestation-age 300 \
  --on-missing-attestation fail
```

## Optional external agent attestation

Use this when you want a runtime identity layer on top of server scoring.

`mcp-trust-radar` scores **server risk posture**. Attestation policy gates on **agent trust posture**.

Supported trust score keys:

- `trust_score`
- `score`
- `agent_trust_score`

Supported timestamp keys:

- `attested_at` (ISO-8601 or epoch)
- `timestamp` (epoch)
- `issued_at` (ISO-8601 or epoch)

Example payload:

```json
{
  "agent_id": "agent-runner-42",
  "trust_score": 78,
  "attested_at": "2026-03-31T22:00:00Z"
}
```

## Input fields for access posture

`auth_required` and `exposed_publicly` are optional booleans. When provided, they influence score:

- Public + no auth gets a heavy penalty
- Public + auth gets a smaller penalty
- Missing fields keep backward-compatible scoring behavior

```json
{
  "name": "ticket-helper",
  "permissions": ["issues:read", "issues:update"],
  "auth_required": true,
  "exposed_publicly": true
}
```

## Input fields for prompt-injection posture

`prompt_injection_controls` is optional. It accepts either a JSON array or a comma-separated string.

Recognized controls:

- `allowlist_only_tools`
- `tool_description_sanitization`
- `server_instruction_sanitization`
- `tool_argument_validation`
- `resource_content_sanitization`
- `human_approval_for_writes`

Scoring behavior:

- Missing field = no prompt-injection adjustment (backward compatible)
- High-risk/public servers with weak or empty controls receive a penalty
- Better control coverage earns a positive adjustment
- Command-capable servers receive an additional safeguard adjustment:
  - `allowlist_only_tools` + `human_approval_for_writes`: bonus
  - only one of those controls: penalty
  - neither control: heavy penalty

```json
{
  "name": "ops-helper",
  "permissions": ["shell:exec", "filesystem:write", "network:http"],
  "auth_required": true,
  "exposed_publicly": true,
  "prompt_injection_controls": [
    "allowlist_only_tools",
    "tool_description_sanitization",
    "tool_argument_validation",
    "human_approval_for_writes"
  ]
}
```

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
