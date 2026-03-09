from __future__ import annotations

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings
from .models import AnalyzeRequest, AnalyzeResponse, KillRequest, KillResponse, SessionMetadata
from .services.gemini import GeminiAnalyzer
from .services.teamviewer import TeamViewerClient


def require_login(x_sentinelflow_user: str | None = Header(default=None)) -> None:
    """
    Minimal "Login Gate" for the MVP: Streamlit passes the username in a header
    after validating credentials client-side. This endpoint ensures the header
    is present and matches the configured username.
    """
    if not x_sentinelflow_user or x_sentinelflow_user != settings.sentinelflow_login_username:
        raise HTTPException(status_code=401, detail="Unauthorized")


app = FastAPI(title="SentinelFlow AI Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/sessions", response_model=list[SessionMetadata])
async def sessions(_: None = Depends(require_login), limit: int = 50) -> list[SessionMetadata]:
    tv = TeamViewerClient()
    return await tv.list_sessions(limit=limit)


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest, _: None = Depends(require_login)) -> AnalyzeResponse:
    analyzer = GeminiAnalyzer()
    assessments = {}
    for s in payload.sessions:
        res = await analyzer.assess(s)
        assessments[s.session_id] = res.assessment
    return AnalyzeResponse(assessments=assessments)


@app.post("/kill", response_model=KillResponse)
async def kill(req: KillRequest, _: None = Depends(require_login)) -> KillResponse:
    tv = TeamViewerClient()
    ok, msg = await tv.terminate_session(req.session_id)
    reason = f" Reason: {req.reason}" if req.reason else ""
    return KillResponse(session_id=req.session_id, terminated=ok, message=msg + reason)

