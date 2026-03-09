from __future__ import annotations

from dataclasses import dataclass

from datetime import timezone

from ..core.config import settings
from ..models import RiskAssessment, SessionMetadata


@dataclass(frozen=True)
class GeminiResult:
    assessment: RiskAssessment


class GeminiAnalyzer:
    def __init__(self) -> None:
        self._api_key = (settings.gemini_api_key or "").strip()
        self._model = (settings.gemini_model or "gemini-2.0-flash").strip()

    async def assess(self, session: SessionMetadata) -> GeminiResult:
        if not self._api_key:
            return GeminiResult(assessment=self._heuristic_assess(session))

        # Lazy import to avoid hard failure if user doesn't configure Gemini.
        from google import genai  # type: ignore

        client = genai.Client(api_key=self._api_key)

        prompt = self._build_prompt(session)
        resp = client.models.generate_content(
            model=self._model,
            contents=prompt,
        )

        text = getattr(resp, "text", None) or ""
        assessment = self._parse_or_fallback(text=text, session=session)
        return GeminiResult(assessment=assessment)

    @staticmethod
    def _build_prompt(session: SessionMetadata) -> str:
        geo = session.geo.model_dump() if session.geo else None
        return (
            "You are SentinelFlow AI, a security analyst. Given a single remote desktop session's metadata, "
            "produce a risk score (0-100), a risk level (low/medium/high/critical), concise reasoning, and "
            "a bullet list of key signals. Keep it short.\n\n"
            f"Session ID: {session.session_id}\n"
            f"Remote user: {session.remote_user}\n"
            f"Device ID: {session.device_id}\n"
            f"Start time (UTC): {session.start_time.isoformat()}\n"
            f"End time (UTC): {(session.end_time.isoformat() if session.end_time else 'active/unknown')}\n"
            f"Source IP: {session.source_ip}\n"
            f"Geo: {geo}\n"
            f"Raw: {session.raw}\n\n"
            "Return STRICT JSON with keys: score (int), level (string), reasoning (string), signals (array of strings)."
        )

    @staticmethod
    def _parse_or_fallback(text: str, session: SessionMetadata) -> RiskAssessment:
        import json

        try:
            start = text.find("{")
            end = text.rfind("}")
            if start == -1 or end == -1 or end <= start:
                raise ValueError("No JSON object found.")
            payload = json.loads(text[start : end + 1])
            return RiskAssessment(
                score=int(payload["score"]),
                level=str(payload["level"]),
                reasoning=str(payload["reasoning"]),
                signals=[str(s) for s in (payload.get("signals") or [])],
            )
        except Exception:  # noqa: BLE001
            return GeminiAnalyzer._heuristic_assess(session, extra_reason=text.strip()[:800])

    @staticmethod
    def _heuristic_assess(session: SessionMetadata, extra_reason: str | None = None) -> RiskAssessment:
        signals: list[str] = []
        score = 10

        user = (session.remote_user or "").lower()
        if user in {"unknown", "svc-automation", "service", "admin"}:
            score += 20
            signals.append(f"suspicious or generic user '{session.remote_user}'")

        start_dt = session.start_time
        if start_dt.tzinfo is None:
            start_dt = start_dt.replace(tzinfo=timezone.utc)
        hour_utc = start_dt.astimezone(timezone.utc).hour
        if hour_utc >= 22 or hour_utc < 5:
            score += 20
            signals.append("off-hours activity (22:00–05:00 UTC)")

        country = (session.geo.country if session.geo else None) or ""
        if country.upper() in {"RU", "KP", "IR"}:
            score += 35
            signals.append(f"source geolocation country '{country}' elevated risk")

        if session.end_time is None:
            score += 10
            signals.append("active session (no end time)")

        if session.source_ip and session.source_ip.startswith(("10.", "192.168.", "172.16.")):
            score -= 5
            signals.append("private RFC1918 source IP (likely internal)")

        score = max(0, min(100, score))
        if score >= 85:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 30:
            level = "medium"
        else:
            level = "low"

        reasoning = "Heuristic risk assessment based on available metadata."
        if extra_reason:
            reasoning += f" Model output (unparsed): {extra_reason}"

        return RiskAssessment(score=score, level=level, reasoning=reasoning, signals=signals)

