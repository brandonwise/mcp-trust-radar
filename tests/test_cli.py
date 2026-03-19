import pytest

from mcp_trust_radar.cli import build_parser, evaluate_gate
from mcp_trust_radar.models import Server
from mcp_trust_radar.scoring import score_server


def _sample_scores():
    trusted = score_server(
        Server(
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
    )
    caution = score_server(
        Server(
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
    )
    return [trusted, caution]


def test_parser_score_command():
    parser = build_parser()
    args = parser.parse_args(["score", "--input", "servers.json"])
    assert args.command == "score"
    assert args.input == "servers.json"
    assert args.minimum_tier == "review"


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
