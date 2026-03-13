from mcp_trust_radar.models import Server, parse_servers
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


def test_public_unauthenticated_server_is_penalized_vs_authenticated():
    baseline = {
        "name": "public-api",
        "permissions": ["docs:read"],
        "stars": 60,
        "open_issues": 8,
        "last_commit_days_ago": 20,
        "license": "MIT",
        "maintainers": 2,
        "exposed_publicly": True,
    }

    authenticated = score_server(Server(**baseline, auth_required=True))
    unauthenticated = score_server(Server(**baseline, auth_required=False))

    assert authenticated.score > unauthenticated.score
    assert unauthenticated.breakdown.auth_penalty == 18
    assert unauthenticated.breakdown.exposure_penalty == 12


def test_parse_servers_supports_list_input_and_boolean_strings():
    servers = parse_servers(
        [
            {
                "name": "ingress",
                "auth_required": "yes",
                "exposed_publicly": "0",
            }
        ]
    )

    assert len(servers) == 1
    assert servers[0].auth_required is True
    assert servers[0].exposed_publicly is False
