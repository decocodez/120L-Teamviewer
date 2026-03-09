from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class GeoInfo(BaseModel):
    ip: str
    country: str | None = None
    region: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None


class SessionMetadata(BaseModel):
    session_id: str
    device_id: str | None = None
    remote_user: str | None = None
    start_time: datetime
    end_time: datetime | None = None
    source_ip: str | None = None
    geo: GeoInfo | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class RiskAssessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: Literal["low", "medium", "high", "critical"]
    reasoning: str
    signals: list[str] = Field(default_factory=list)


class AnalyzeRequest(BaseModel):
    sessions: list[SessionMetadata]


class AnalyzeResponse(BaseModel):
    assessments: dict[str, RiskAssessment]


class KillRequest(BaseModel):
    session_id: str
    reason: str | None = None


class KillResponse(BaseModel):
    session_id: str
    terminated: bool
    message: str

