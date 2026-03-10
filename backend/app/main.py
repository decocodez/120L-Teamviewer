from __future__ import annotations
import logging
import sys
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from .core.config import settings
from .models import AnalyzeRequest, AnalyzeResponse, KillRequest, KillResponse, SessionMetadata
from .services.gemini import GeminiAnalyzer
from .services.teamviewer import TeamViewerClient

# --- RENDER-COMPATIBLE LOGGING ---
logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="%(levelname)s:     %(message)s"
)
logger = logging.getLogger("sentinelflow")

def require_login(x_sentinelflow_user: str | None = Header(default=None)) -> None:
    """Checks the header passed by Streamlit against the environment config."""
    if not x_sentinelflow_user or x_sentinelflow_user != settings.sentinelflow_login_username:
        logger.warning(f"Unauthorized access attempt: {x_sentinelflow_user}")
        raise HTTPException(status_code=401, detail="Unauthorized")

app = FastAPI(title="SentinelFlow AI Backend", version="0.1.0")

# --- CORS CONFIGURATION ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:8501",
        "https://sentinelflow-frontend.onrender.com",
        "https://120l-teamviewer.streamlit.app", # Streamlit Cloud
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/sessions", response_model=list[SessionMetadata])
async def sessions(_: None = Depends(require_login), limit: int = 50) -> list[SessionMetadata]:
    logger.info(f"Fetching up to {limit} sessions from TeamViewer...")
    tv = TeamViewerClient()
    data = await tv.list_sessions(limit=limit)
    logger.info(f"Retrieved {len(data)} sessions.")
    return data

@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze(payload: AnalyzeRequest, _: None = Depends(require_login)) -> AnalyzeResponse:
    analyzer = GeminiAnalyzer()
    assessments = {}
    
    logger.info(f"AI ANALYSIS START: {len(payload.sessions)} items in queue.")
    
    for s in payload.sessions:
        logger.info(f"Investigating: {s.session_id} (User: {s.remote_user})")
        res = await analyzer.assess(s)
        assessments[s.session_id] = res.assessment
        logger.info(f"Result: {res.assessment.level.upper()} | Score: {res.assessment.score}")
        
    logger.info("🏁 AI Analysis cycle complete.")
    return AnalyzeResponse(assessments=assessments)

@app.post("/kill", response_model=KillResponse)
async def kill(req: KillRequest, _: None = Depends(require_login)) -> KillResponse:
    logger.warning(f"TERMINATION REQUESTED: Session {req.session_id}")
    tv = TeamViewerClient()
    ok, msg = await tv.terminate_session(req.session_id)
    reason = f" Reason: {req.reason}" if req.reason else ""
    
    if ok:
        logger.info(f"Session {req.session_id} successfully terminated.")
    else:
        logger.error(f"Termination failed: {msg}")
        
    return KillResponse(session_id=req.session_id, terminated=ok, message=msg + reason)
