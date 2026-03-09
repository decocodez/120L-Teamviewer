from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from ..core.config import settings
from ..models import GeoInfo, SessionMetadata


_terminated_mock_sessions: set[str] = set()


class TeamViewerClient:
    def __init__(self) -> None:
        self._base_url = settings.teamviewer_base_url.rstrip("/")
        self._token = (settings.teamviewer_api_token or "").strip()

    def _headers(self) -> dict[str, str]:
        if not self._token:
            return {}
        return {"Authorization": f"Bearer {self._token}"}

    async def list_sessions(self, limit: int = 50) -> list[SessionMetadata]:
        """
        If TEAMVIEWER_API_TOKEN is not configured, returns deterministic mock sessions.
        """
        if not self._token:
            sessions = self._mock_sessions(limit=limit)
            if _terminated_mock_sessions:
                sessions = [s for s in sessions if s.session_id not in _terminated_mock_sessions]
            return sessions

        # NOTE: TeamViewer API resource names differ by plan/account. This implementation
        # is intentionally conservative and may need tweaking once you confirm the exact
        # endpoint available for your token.
        #
        # Many accounts expose connection/audit data via an "events" feed. We attempt
        # a small set of common endpoints and gracefully fallback.
        candidates = [
            f"{self._base_url}/events",
            f"{self._base_url}/connections",
            f"{self._base_url}/sessions",
        ]

        async with httpx.AsyncClient(timeout=20) as client:
            last_error: str | None = None
            for url in candidates:
                try:
                    r = await client.get(url, headers=self._headers(), params={"limit": limit})
                    if r.status_code == 404:
                        last_error = f"{url} -> 404"
                        continue
                    r.raise_for_status()
                    data = r.json()
                    items = data.get("items") if isinstance(data, dict) else data
                    if not isinstance(items, list):
                        last_error = f"{url} -> unexpected payload"
                        continue
                    return [self._to_session(item) for item in items][:limit]
                except Exception as e:  # noqa: BLE001
                    last_error = f"{url} -> {type(e).__name__}: {e}"
                    continue

        raise RuntimeError(f"Unable to fetch TeamViewer sessions. Last error: {last_error}")

    async def terminate_session(self, session_id: str) -> tuple[bool, str]:
        if not self._token:
            _terminated_mock_sessions.add(session_id)
            return True, "Mock termination succeeded for demo session (no TEAMVIEWER_API_TOKEN configured)."

        # TeamViewer termination differs; we try common patterns.
        candidates = [
            (f"{self._base_url}/sessions/{session_id}/terminate", "POST"),
            (f"{self._base_url}/connections/{session_id}/terminate", "POST"),
            (f"{self._base_url}/sessions/{session_id}", "DELETE"),
        ]

        async with httpx.AsyncClient(timeout=20) as client:
            last_error: str | None = None
            for url, method in candidates:
                try:
                    if method == "POST":
                        r = await client.post(url, headers=self._headers())
                    else:
                        r = await client.delete(url, headers=self._headers())
                    if r.status_code == 404:
                        last_error = f"{method} {url} -> 404"
                        continue
                    r.raise_for_status()
                    return True, f"Termination request accepted via {method} {url}."
                except Exception as e:  # noqa: BLE001
                    last_error = f"{method} {url} -> {type(e).__name__}: {e}"
                    continue
        return False, f"Unable to terminate session. Last error: {last_error}"

    def _to_session(self, item: dict[str, Any]) -> SessionMetadata:
        session_id = str(item.get("id") or item.get("session_id") or item.get("connection_id") or "")
        device_id = item.get("device_id") or item.get("deviceId")
        remote_user = item.get("user") or item.get("remote_user") or item.get("remoteUser")
        start = item.get("start_time") or item.get("startTime") or item.get("timestamp") or item.get("time")
        end = item.get("end_time") or item.get("endTime")
        source_ip = item.get("source_ip") or item.get("ip") or item.get("sourceIp")

        start_dt = self._parse_dt(start) or datetime.now(tz=timezone.utc)
        end_dt = self._parse_dt(end) if end else None

        geo = None
        if isinstance(item.get("geo"), dict):
            g = item["geo"]
            geo = GeoInfo(
                ip=str(g.get("ip") or source_ip or ""),
                country=g.get("country"),
                region=g.get("region"),
                city=g.get("city"),
                lat=g.get("lat"),
                lon=g.get("lon"),
            )

        return SessionMetadata(
            session_id=session_id or f"unknown-{int(start_dt.timestamp())}",
            device_id=str(device_id) if device_id is not None else None,
            remote_user=str(remote_user) if remote_user is not None else None,
            start_time=start_dt,
            end_time=end_dt,
            source_ip=str(source_ip) if source_ip is not None else None,
            geo=geo,
            raw=item,
        )

    @staticmethod
    def _parse_dt(value: Any) -> datetime | None:
        if value is None:
            return None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        if isinstance(value, str):
            v = value.strip()
            try:
                # ISO 8601-ish
                if v.endswith("Z"):
                    v = v[:-1] + "+00:00"
                dt = datetime.fromisoformat(v)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except Exception:  # noqa: BLE001
                return None
        return None

    @staticmethod
    def _mock_sessions(limit: int) -> list[SessionMetadata]:
        now = datetime.now(tz=timezone.utc)
        base = now - timedelta(hours=2)
        mocks: list[SessionMetadata] = []
        for i in range(min(limit, 12)):
            start = base + timedelta(minutes=i * 7)
            end = start + timedelta(minutes=5 + (i % 4) * 3)
            ip = f"203.0.113.{10+i}"
            country = "US" if i % 3 else "RU"
            mocks.append(
                SessionMetadata(
                    session_id=f"mock-{1000+i}",
                    device_id=f"dev-{(i%4)+1}",
                    remote_user=["alice", "bob", "svc-automation", "unknown"][i % 4],
                    start_time=start,
                    end_time=end if i % 5 else None,
                    source_ip=ip,
                    geo=GeoInfo(ip=ip, country=country, region=None, city=None, lat=None, lon=None),
                    raw={"mock": True, "index": i},
                )
            )
        return mocks

