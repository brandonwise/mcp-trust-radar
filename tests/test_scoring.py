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


def test_public_server_without_tls_is_penalized_vs_tls_enforced():
    baseline = {
        "name": "public-api",
        "permissions": ["docs:read"],
        "stars": 60,
        "open_issues": 8,
        "last_commit_days_ago": 20,
        "license": "MIT",
        "maintainers": 2,
        "auth_required": True,
        "exposed_publicly": True,
    }

    with_tls = score_server(Server(**baseline, tls_enforced=True))
    without_tls = score_server(Server(**baseline, tls_enforced=False))

    assert with_tls.score > without_tls.score
    assert with_tls.breakdown.tls_penalty == 0
    assert without_tls.breakdown.tls_penalty == 10


def test_prompt_injection_controls_raise_score_for_public_server():
    base = {
        "name": "public-helper",
        "permissions": ["issues:update", "network:http"],
        "stars": 120,
        "open_issues": 6,
        "last_commit_days_ago": 14,
        "license": "MIT",
        "maintainers": 3,
        "auth_required": True,
        "exposed_publicly": True,
    }

    without_controls = score_server(Server(**base, prompt_injection_controls=[]))
    with_controls = score_server(
        Server(
            **base,
            prompt_injection_controls=[
                "allowlist_only_tools",
                "tool_description_sanitization",
                "tool_argument_validation",
            ],
        )
    )

    assert with_controls.score > without_controls.score
    assert with_controls.breakdown.injection_adjustment > without_controls.breakdown.injection_adjustment
    assert with_controls.breakdown.injection_label in {"moderate", "strong"}


def test_shared_service_account_is_penalized_vs_per_user_credentials():
    base = {
        "name": "public-helper",
        "permissions": ["issues:update", "network:http"],
        "stars": 120,
        "open_issues": 6,
        "last_commit_days_ago": 14,
        "license": "MIT",
        "maintainers": 3,
        "auth_required": True,
        "exposed_publicly": True,
        "prompt_injection_controls": [
            "allowlist_only_tools",
            "tool_description_sanitization",
            "tool_argument_validation",
        ],
    }

    per_user = score_server(
        Server(
            **base,
            credential_posture="per-user",
            credential_controls=[
                "scoped_tokens",
                "short_lived_tokens",
                "resource_scoped_tokens",
            ],
        )
    )
    shared = score_server(
        Server(
            **base,
            credential_posture="shared-service-account",
            credential_controls=[],
        )
    )

    assert per_user.score > shared.score
    assert per_user.breakdown.credential_posture_adjustment > (
        shared.breakdown.credential_posture_adjustment
    )
    assert shared.breakdown.credential_posture_label == "shared-service-account"


def test_credential_controls_raise_score_for_risk_surface_server():
    base = {
        "name": "ops-helper",
        "permissions": ["issues:update", "network:http"],
        "stars": 40,
        "open_issues": 4,
        "last_commit_days_ago": 15,
        "license": "MIT",
        "maintainers": 2,
        "auth_required": True,
        "exposed_publicly": True,
        "credential_posture": "service-account",
    }

    without_controls = score_server(Server(**base, credential_controls=[]))
    with_controls = score_server(
        Server(
            **base,
            credential_controls=[
                "scoped_tokens",
                "short_lived_tokens",
                "resource_scoped_tokens",
                "token_rotation",
            ],
        )
    )

    assert with_controls.score > without_controls.score
    assert with_controls.breakdown.credential_posture_adjustment > (
        without_controls.breakdown.credential_posture_adjustment
    )


def test_command_capable_server_is_penalized_without_execution_safeguards():
    base = {
        "name": "command-runner",
        "permissions": ["shell:exec", "network:http"],
        "stars": 80,
        "open_issues": 4,
        "last_commit_days_ago": 12,
        "license": "MIT",
        "maintainers": 2,
        "auth_required": True,
        "exposed_publicly": False,
    }

    without_safeguards = score_server(
        Server(
            **base,
            prompt_injection_controls=["tool_argument_validation"],
        )
    )
    with_safeguards = score_server(
        Server(
            **base,
            prompt_injection_controls=[
                "allowlist_only_tools",
                "tool_argument_validation",
                "human_approval_for_writes",
            ],
        )
    )

    assert with_safeguards.score > without_safeguards.score
    assert with_safeguards.breakdown.command_safeguard_adjustment > (
        without_safeguards.breakdown.command_safeguard_adjustment
    )
    assert any(
        "Command-execution capabilities detected" in note
        for note in with_safeguards.breakdown.command_safeguard_notes
    )


def test_non_command_server_gets_neutral_command_safeguard_adjustment():
    scored = score_server(
        Server(
            name="readonly-docs",
            permissions=["docs:read"],
            stars=30,
            open_issues=1,
            last_commit_days_ago=15,
            license="MIT",
            maintainers=2,
            prompt_injection_controls=["allowlist_only_tools"],
        )
    )

    assert scored.breakdown.command_safeguard_adjustment == 0
    assert any(
        "No command-execution capabilities detected" in note
        for note in scored.breakdown.command_safeguard_notes
    )


def test_prompt_injection_controls_absent_stays_unknown():
    scored = score_server(
        Server(
            name="unknown-controls",
            permissions=["docs:read"],
            stars=10,
            open_issues=1,
            last_commit_days_ago=20,
            license="MIT",
            maintainers=1,
        )
    )

    assert scored.breakdown.injection_label == "unknown"
    assert scored.breakdown.injection_adjustment == 0


def test_parse_servers_supports_list_input_and_boolean_strings():
    servers = parse_servers(
        [
            {
                "name": "ingress",
                "auth_required": "yes",
                "exposed_publicly": "0",
                "tls_enforced": "true",
                "prompt_injection_controls": "allowlist_only_tools,tool_argument_validation",
                "credential_posture": "shared_service_account",
                "credential_controls": "scoped_tokens,short_lived_tokens",
            }
        ]
    )

    assert len(servers) == 1
    assert servers[0].auth_required is True
    assert servers[0].exposed_publicly is False
    assert servers[0].tls_enforced is True
    assert servers[0].prompt_injection_controls == [
        "allowlist_only_tools",
        "tool_argument_validation",
    ]
    assert servers[0].credential_posture == "shared_service_account"
    assert servers[0].credential_controls == ["scoped_tokens", "short_lived_tokens"]
