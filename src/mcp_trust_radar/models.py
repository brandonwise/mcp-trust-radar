from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class Server:
    name: str
    repo: Optional[str] = None
    permissions: List[str] = field(default_factory=list)
    stars: int = 0
    open_issues: int = 0
    last_commit_days_ago: Optional[int] = None
    license: Optional[str] = None
    maintainers: int = 1
    auth_required: Optional[bool] = None
    exposed_publicly: Optional[bool] = None
    tls_enforced: Optional[bool] = None
    prompt_injection_controls: Optional[List[str]] = None


@dataclass
class RiskBreakdown:
    permission_risk: float
    permission_label: str
    permission_notes: List[str]
    stale_penalty: int
    issue_penalty: int
    popularity_bonus: int
    license_adjustment: int
    maintainer_bonus: int
    auth_penalty: int
    exposure_penalty: int
    auth_notes: List[str]
    tls_penalty: int
    tls_notes: List[str]
    injection_adjustment: int
    injection_label: str
    injection_notes: List[str]
    command_safeguard_adjustment: int
    command_safeguard_notes: List[str]


@dataclass
class TrustScore:
    name: str
    score: int
    tier: str
    breakdown: RiskBreakdown


def _as_optional_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "t", "yes", "y"}:
            return True
        if normalized in {"0", "false", "f", "no", "n"}:
            return False
    raise ValueError(f"Expected a boolean-compatible value, got: {value!r}")


def _as_string_list(value: Any, field_name: str) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]

    if isinstance(value, list):
        out: List[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                out.append(text)
        return out

    raise ValueError(f"Expected '{field_name}' to be a list or comma-separated string, got: {value!r}")


def parse_servers(data: Any) -> List[Server]:
    if isinstance(data, dict):
        payload = data.get("servers", data)
    else:
        payload = data

    if not isinstance(payload, list):
        raise ValueError("Input must be a list or an object with a 'servers' list")

    servers: List[Server] = []
    for raw in payload:
        controls = (
            _as_string_list(raw.get("prompt_injection_controls"), "prompt_injection_controls")
            if "prompt_injection_controls" in raw
            else None
        )

        servers.append(
            Server(
                name=str(raw["name"]),
                repo=(str(raw["repo"]) if raw.get("repo") else None),
                permissions=[str(p) for p in (raw.get("permissions") or [])],
                stars=int(raw.get("stars", 0) or 0),
                open_issues=int(raw.get("open_issues", 0) or 0),
                last_commit_days_ago=(
                    int(raw["last_commit_days_ago"])
                    if raw.get("last_commit_days_ago") is not None
                    else None
                ),
                license=(str(raw["license"]) if raw.get("license") else None),
                maintainers=int(raw.get("maintainers", 1) or 1),
                auth_required=_as_optional_bool(raw.get("auth_required")),
                exposed_publicly=_as_optional_bool(raw.get("exposed_publicly")),
                tls_enforced=_as_optional_bool(raw.get("tls_enforced")),
                prompt_injection_controls=controls,
            )
        )

    return servers
