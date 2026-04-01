from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union


@dataclass
class AgentAttestation:
    trust_score: int
    attested_at_epoch: Optional[int] = None
    agent_id: Optional[str] = None


def _parse_timestamp_to_epoch(value: Any) -> Optional[int]:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        return int(value)

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None

        # Numeric string epoch support
        if raw.isdigit():
            return int(raw)

        # ISO-8601 support (including trailing Z)
        iso = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())

    raise ValueError(f"Unsupported attestation timestamp type: {type(value).__name__}")


def _first_present(payload: Dict[str, Any], keys: Tuple[str, ...]) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def parse_attestation_dict(data: Dict[str, Any]) -> AgentAttestation:
    if not isinstance(data, dict):
        raise ValueError("Attestation payload must be a JSON object")

    trust_score_raw = _first_present(data, ("trust_score", "score", "agent_trust_score"))
    if trust_score_raw is None:
        raise ValueError(
            "Attestation payload must include trust score (trust_score|score|agent_trust_score)"
        )

    try:
        trust_score = int(trust_score_raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid trust score value: {trust_score_raw!r}") from exc

    if not (0 <= trust_score <= 100):
        raise ValueError("Attestation trust score must be between 0 and 100")

    ts_raw = _first_present(data, ("attested_at", "timestamp", "issued_at"))
    attested_at_epoch = _parse_timestamp_to_epoch(ts_raw)

    agent_id_raw = _first_present(data, ("agent_id", "agent", "subject"))
    agent_id = str(agent_id_raw).strip() if agent_id_raw is not None else None
    if agent_id == "":
        agent_id = None

    return AgentAttestation(
        trust_score=trust_score,
        attested_at_epoch=attested_at_epoch,
        agent_id=agent_id,
    )


def parse_attestation_file(path: Union[str, Path]) -> AgentAttestation:
    import json

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return parse_attestation_dict(payload)


def evaluate_attestation_policy(
    *,
    attestation: Optional[AgentAttestation],
    min_agent_trust: Optional[int],
    max_attestation_age: Optional[int],
    on_missing_attestation: str,
    now_epoch: Optional[int] = None,
) -> Tuple[bool, list[str], list[str]]:
    """Evaluate attestation gates.

    Returns: (passed, failures, warnings)
    """
    if on_missing_attestation not in {"ignore", "warn", "fail"}:
        raise ValueError("--on-missing-attestation must be one of: ignore, warn, fail")

    if min_agent_trust is not None and not (0 <= min_agent_trust <= 100):
        raise ValueError("--min-agent-trust must be between 0 and 100")

    if max_attestation_age is not None and max_attestation_age < 0:
        raise ValueError("--max-attestation-age must be >= 0")

    failures: list[str] = []
    warnings: list[str] = []

    policy_enabled = min_agent_trust is not None or max_attestation_age is not None

    if attestation is None:
        if policy_enabled:
            message = (
                "Agent attestation is missing while attestation policy is configured"
            )
            if on_missing_attestation == "fail":
                failures.append(message)
            elif on_missing_attestation == "warn":
                warnings.append(message)
        return len(failures) == 0, failures, warnings

    if min_agent_trust is not None and attestation.trust_score < min_agent_trust:
        failures.append(
            f"Agent trust score {attestation.trust_score} is below minimum {min_agent_trust}"
        )

    if max_attestation_age is not None:
        if attestation.attested_at_epoch is None:
            message = (
                "Agent attestation timestamp missing while max-attestation-age is configured"
            )
            if on_missing_attestation == "fail":
                failures.append(message)
            elif on_missing_attestation == "warn":
                warnings.append(message)
        else:
            now = int(now_epoch) if now_epoch is not None else int(datetime.now(timezone.utc).timestamp())
            age = max(0, now - attestation.attested_at_epoch)
            if age > max_attestation_age:
                failures.append(
                    f"Agent attestation age {age}s exceeds maximum {max_attestation_age}s"
                )

    return len(failures) == 0, failures, warnings
