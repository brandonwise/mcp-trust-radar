import json
from pathlib import Path

import pytest

from mcp_trust_radar.attestation import (
    AgentAttestation,
    evaluate_attestation_policy,
    parse_attestation_dict,
    parse_attestation_file,
)


def test_parse_attestation_dict_accepts_alias_keys_and_iso_timestamp():
    att = parse_attestation_dict(
        {
            "score": 72,
            "attested_at": "2026-03-31T22:00:00Z",
            "agent_id": "agent-7",
        }
    )

    assert isinstance(att, AgentAttestation)
    assert att.trust_score == 72
    assert att.attested_at_epoch is not None
    assert att.agent_id == "agent-7"


def test_parse_attestation_dict_rejects_out_of_range_score():
    with pytest.raises(ValueError):
        parse_attestation_dict({"trust_score": 120})


def test_parse_attestation_file_round_trip(tmp_path: Path):
    p = tmp_path / "attestation.json"
    p.write_text(
        json.dumps(
            {
                "trust_score": 80,
                "timestamp": 1774990000,
                "subject": "bot-alpha",
            }
        ),
        encoding="utf-8",
    )

    att = parse_attestation_file(p)
    assert att.trust_score == 80
    assert att.attested_at_epoch == 1774990000
    assert att.agent_id == "bot-alpha"


def test_attestation_policy_warns_when_missing_and_required():
    passed, failures, warnings = evaluate_attestation_policy(
        attestation=None,
        min_agent_trust=70,
        max_attestation_age=None,
        on_missing_attestation="warn",
    )

    assert passed is True
    assert failures == []
    assert len(warnings) == 1
    assert "missing" in warnings[0].lower()


def test_attestation_policy_fails_when_missing_and_fail_mode():
    passed, failures, warnings = evaluate_attestation_policy(
        attestation=None,
        min_agent_trust=70,
        max_attestation_age=300,
        on_missing_attestation="fail",
    )

    assert passed is False
    assert warnings == []
    assert any("missing" in f.lower() for f in failures)


def test_attestation_policy_fails_when_score_below_minimum():
    passed, failures, warnings = evaluate_attestation_policy(
        attestation=AgentAttestation(trust_score=55, attested_at_epoch=1774990000),
        min_agent_trust=60,
        max_attestation_age=None,
        on_missing_attestation="warn",
        now_epoch=1774990100,
    )

    assert passed is False
    assert warnings == []
    assert any("below minimum" in f.lower() for f in failures)


def test_attestation_policy_fails_when_attestation_too_old():
    passed, failures, warnings = evaluate_attestation_policy(
        attestation=AgentAttestation(trust_score=80, attested_at_epoch=1774990000),
        min_agent_trust=None,
        max_attestation_age=60,
        on_missing_attestation="warn",
        now_epoch=1774990200,
    )

    assert passed is False
    assert warnings == []
    assert any("exceeds" in f.lower() for f in failures)


def test_attestation_policy_passes_when_thresholds_met():
    passed, failures, warnings = evaluate_attestation_policy(
        attestation=AgentAttestation(trust_score=81, attested_at_epoch=1774990000),
        min_agent_trust=70,
        max_attestation_age=300,
        on_missing_attestation="warn",
        now_epoch=1774990100,
    )

    assert passed is True
    assert failures == []
    assert warnings == []
