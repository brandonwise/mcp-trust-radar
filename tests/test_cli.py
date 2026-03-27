import pytest

from mcp_trust_radar.cli import build_parser, evaluate_gate
from mcp_trust_radar.models import Server
from mcp_trust_radar.scoring import score_server


def _sample_servers():
    trusted = Server(
        name="safe-docs",
        permissions=["docs:read"],
        stars=500,
        open_issues=5,
        last_commit_days_ago=10,
        license="MIT",
        maintainers=4,
        auth_required=True,
        exposed_publicly=False,
    )
    caution = Server(
        name="danger-bot",
        permissions=["shell:exec", "filesystem:write", "network:http"],
        stars=8,
        open_issues=60,
        last_commit_days_ago=500,
        license=None,
        maintainers=1,
        auth_required=False,
        exposed_publicly=True,
        prompt_injection_controls=[],
    )
    return [trusted, caution]


def _sample_scores():
    return [score_server(server) for server in _sample_servers()]


def test_parser_score_command():
    parser = build_parser()
    args = parser.parse_args(["score", "--input", "servers.json"])
    assert args.command == "score"
    assert args.input == "servers.json"
    assert args.minimum_tier == "review"
    assert args.block_public_without_auth is False
    assert args.minimum_public_controls is None
    assert args.minimum_risk_surface_controls is None


def test_evaluate_gate_blocks_caution_by_default():
    passed, reasons = evaluate_gate(_sample_scores())
    assert passed is False
    assert any("below minimum tier 'review'" in r for r in reasons)


def test_evaluate_gate_allows_caution_when_threshold_is_caution():
    passed, reasons = evaluate_gate(_sample_scores(), minimum_tier="caution")
    assert passed is True
    assert reasons == []


def test_evaluate_gate_can_require_trusted_only():
    passed, reasons = evaluate_gate(_sample_scores(), minimum_tier="trusted")
    assert passed is False
    assert any("below minimum tier 'trusted'" in r for r in reasons)


def test_evaluate_gate_can_enforce_minimum_score():
    passed, reasons = evaluate_gate(_sample_scores(), minimum_tier="caution", minimum_score=80)
    assert passed is False
    assert any("below minimum score 80" in r for r in reasons)


def test_evaluate_gate_rejects_invalid_minimum_score():
    with pytest.raises(ValueError):
        evaluate_gate(_sample_scores(), minimum_score=120)


def test_evaluate_gate_rejects_invalid_minimum_public_controls():
    with pytest.raises(ValueError):
        evaluate_gate(_sample_scores(), minimum_public_controls=9)


def test_evaluate_gate_rejects_invalid_minimum_risk_surface_controls():
    with pytest.raises(ValueError):
        evaluate_gate(_sample_scores(), minimum_risk_surface_controls=7)


def test_evaluate_gate_requires_servers_for_public_policy_checks():
    with pytest.raises(ValueError):
        evaluate_gate(_sample_scores(), block_public_without_auth=True)


def test_evaluate_gate_requires_servers_for_risk_surface_policy_checks():
    with pytest.raises(ValueError):
        evaluate_gate(_sample_scores(), minimum_risk_surface_controls=2)


def test_evaluate_gate_blocks_public_servers_without_auth_when_enabled():
    servers = _sample_servers()
    scores = [score_server(server) for server in servers]

    passed, reasons = evaluate_gate(
        scores,
        minimum_tier="caution",
        servers=servers,
        block_public_without_auth=True,
    )

    assert passed is False
    assert any("missing explicit auth_required=true" in r for r in reasons)


def test_evaluate_gate_blocks_public_servers_with_insufficient_controls_when_enabled():
    servers = _sample_servers()
    scores = [score_server(server) for server in servers]

    passed, reasons = evaluate_gate(
        scores,
        minimum_tier="caution",
        servers=servers,
        minimum_public_controls=2,
    )

    assert passed is False
    assert any("fewer than 2 prompt-injection controls" in r for r in reasons)


def test_evaluate_gate_blocks_risk_surface_servers_with_insufficient_controls():
    servers = [
        Server(
            name="internal-writer",
            permissions=["issues:update", "tickets:create", "jobs:run", "pipeline:patch"],
            stars=40,
            open_issues=5,
            last_commit_days_ago=15,
            license="MIT",
            maintainers=2,
            auth_required=True,
            exposed_publicly=False,
            prompt_injection_controls=["allowlist_only_tools"],
        )
    ]
    scores = [score_server(server) for server in servers]

    passed, reasons = evaluate_gate(
        scores,
        minimum_tier="caution",
        servers=servers,
        minimum_risk_surface_controls=2,
    )

    assert passed is False
    assert any("risk-surface server" in r for r in reasons)
    assert any("internal-writer" in r for r in reasons)


def test_evaluate_gate_passes_when_risk_surface_controls_are_met():
    servers = [
        Server(
            name="internal-secure-writer",
            permissions=["issues:update", "tickets:create", "jobs:run", "pipeline:patch"],
            stars=40,
            open_issues=5,
            last_commit_days_ago=15,
            license="MIT",
            maintainers=2,
            auth_required=True,
            exposed_publicly=False,
            prompt_injection_controls=[
                "allowlist_only_tools",
                "tool_argument_validation",
                "human_approval_for_writes",
            ],
        )
    ]
    scores = [score_server(server) for server in servers]

    passed, reasons = evaluate_gate(
        scores,
        minimum_tier="caution",
        servers=servers,
        minimum_risk_surface_controls=2,
    )

    assert passed is True
    assert reasons == []


def test_evaluate_gate_passes_when_public_policy_requirements_are_met():
    servers = [
        Server(
            name="public-secure",
            permissions=["issues:update", "network:http"],
            stars=120,
            open_issues=8,
            last_commit_days_ago=20,
            license="MIT",
            maintainers=3,
            auth_required=True,
            exposed_publicly=True,
            prompt_injection_controls=[
                "allowlist_only_tools",
                "tool_description_sanitization",
                "tool_argument_validation",
            ],
        )
    ]
    scores = [score_server(server) for server in servers]

    passed, reasons = evaluate_gate(
        scores,
        minimum_tier="caution",
        servers=servers,
        block_public_without_auth=True,
        minimum_public_controls=2,
    )

    assert passed is True
    assert reasons == []
