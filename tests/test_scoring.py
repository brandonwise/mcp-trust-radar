from mcp_trust_radar.models import Server
from mcp_trust_radar.scoring import permission_risk, score_server


def test_permission_risk_detects_high_risk_keywords():
    risk, label, notes = permission_risk(["filesystem:write", "shell:exec"])
    assert risk > 5
    assert label in {"medium", "high"}
    assert any("High-risk" in n for n in notes)


def test_safe_server_scores_well():
    server = Server(
        name="safe-docs",
        permissions=["docs:read"],
        stars=500,
        open_issues=5,
        last_commit_days_ago=10,
        license="MIT",
        maintainers=4,
    )
    scored = score_server(server)
    assert scored.score >= 75
    assert scored.tier == "trusted"


def test_risky_server_drops_to_caution():
    server = Server(
        name="danger-bot",
        permissions=["shell:exec", "filesystem:write", "network:http"],
        stars=8,
        open_issues=60,
        last_commit_days_ago=500,
        license=None,
        maintainers=1,
    )
    scored = score_server(server)
    assert scored.score < 55
    assert scored.tier == "caution"
