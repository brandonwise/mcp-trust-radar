from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Optional

import requests


def fetch_repo_metadata(repo: str, token: Optional[str] = None) -> Dict:
    url = f"https://api.github.com/repos/{repo}"
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    response = requests.get(url, headers=headers, timeout=15)
    response.raise_for_status()
    data = response.json()

    pushed_at = data.get("pushed_at")
    days = None
    if pushed_at:
        dt = datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
        days = int((datetime.now(timezone.utc) - dt).days)

    return {
        "stars": int(data.get("stargazers_count", 0) or 0),
        "open_issues": int(data.get("open_issues_count", 0) or 0),
        "license": (data.get("license") or {}).get("spdx_id"),
        "last_commit_days_ago": days,
    }
