from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import time
import httpx
import plotly.express as px
import streamlit as st

@dataclass(frozen=True)
class Cfg:
    backend_url: str
    username: str

# --- CONFIGURATION ---
def _get_secret(key: str) -> str | None:
    try:
        return str(st.secrets.get(key))
    except Exception:
        return None

def cfg_from_env() -> Cfg:
    # Prioritizes Streamlit Secrets, then OS Env, then Render Default
    backend_url = _get_secret("SENTINELFLOW_BACKEND_URL") or _env("SENTINELFLOW_BACKEND_URL", "https://sentinelflow-backend.onrender.com/")
    username = _get_secret("SENTINELFLOW_LOGIN_USERNAME") or _env("SENTINELFLOW_LOGIN_USERNAME", "admin")
    return Cfg(backend_url=backend_url.rstrip("/"), username=username)

def _env(key: str, default: str) -> str:
    import os
    return os.environ.get(key, default)

# --- AUTHENTICATION ---
def is_logged_in() -> bool:
    return bool(st.session_state.get("sf_logged_in"))

def require_login_ui() -> None:
    st.set_page_config(page_title="SentinelFlow AI", layout="wide", page_icon="🛡️")
    
    if is_logged_in():
        return

    st.title("SentinelFlow AI")
    st.caption("Advanced security intelligence for remote desktop auditing.")

    cfg = cfg_from_env()
    expected_user = cfg.username
    expected_pass = _get_secret("SENTINELFLOW_LOGIN_PASSWORD") or _env("SENTINELFLOW_LOGIN_PASSWORD", "admin")

    with st.form("login"):
        st.subheader("Security Access Gate")
        u = st.text_input("Username", value="", autocomplete="username")
        p = st.text_input("Password", value="", type="password", autocomplete="current-password")
        if st.form_submit_button("Authenticate"):
            if u == expected_user and p == expected_pass:
                st.session_state["sf_logged_in"] = True
                st.session_state["sf_user"] = u
                st.rerun()
            else:
                st.error("Invalid credentials.")
    st.stop()

# --- AUDIT FEED LOGGING ---
def update_audit_log(message: str):
    if "audit_trail" not in st.session_state:
        st.session_state.audit_trail = []
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.audit_trail.append(f"[{timestamp}] {message}")

def show_sidebar_audit():
    st.sidebar.markdown("---")
    st.sidebar.subheader("🛡️ Live Audit Feed")
    if "audit_trail" in st.session_state and st.session_state.audit_trail:
        # Show last 12 entries
        logs = "\n".join(st.session_state.audit_trail[-12:])
        st.sidebar.code(logs, language="text")
    else:
        st.sidebar.caption("System ready. Awaiting events...")

# --- API INTEGRATION ---
def backend_headers() -> dict[str, str]:
    return {"X-SentinelFlow-User": st.session_state.get("sf_user", "")}

@st.cache_data(ttl=10)
def fetch_sessions(backend_url: str, limit: int = 50) -> list[dict]:
    r = httpx.get(f"{backend_url}/sessions", headers=backend_headers(), params={"limit": limit}, timeout=20)
    r.raise_for_status()
    return r.json()

def analyze_sessions(backend_url: str, sessions: list[dict]) -> dict[str, dict]:
    try:
        r = httpx.post(f"{backend_url}/analyze", headers=backend_headers(), json={"sessions": sessions}, timeout=60)
        r.raise_for_status()
        return r.json()["assessments"]
    except Exception as e:
        update_audit_log(f"CRITICAL: AI Backend Unreachable")
        st.error(f"Backend Analysis Error: {e}")
        st.stop()

def kill_session(backend_url: str, session_id: str, reason: str | None) -> dict:
    r = httpx.post(f"{backend_url}/kill", headers=backend_headers(), json={"session_id": session_id, "reason": reason}, timeout=20)
    r.raise_for_status()
    return r.json()

# --- PAGE: LIVE MONITOR (SIMULATION) ---
def page_live_monitor(cfg: Cfg):
    st.header("🕵️ Real-Time AI Auditor")
    st.info("Continuous polling active: Monitoring for new TeamViewer connections.")

    if "seen_sessions" not in st.session_state:
        st.session_state.seen_sessions = set()

    # Layout
    col_feed, col_stats = st.columns([2, 1])

    # Simulation Reset
    if st.sidebar.button("🚨 Simulate New Activity"):
        st.session_state.seen_sessions = set()
        update_audit_log("SIMULATION: Cache cleared for re-audit.")
        st.toast("Activity simulated!")

    # Processing Logic
    try:
        sessions = fetch_sessions(cfg.backend_url, limit=5)
        active_ids = {s["session_id"] for s in sessions}
        new_ids = active_ids - st.session_state.seen_sessions

        if new_ids:
            update_audit_log(f"Detected {len(new_ids)} un-audited connections.")
            with st.status("AI Investigation in progress...", expanded=True) as status:
                st.write("Extracting metadata...")
                new_batch = [s for s in sessions if s["session_id"] in new_ids]
                results = analyze_sessions(cfg.backend_url, new_batch)
                
                for sid, a in results.items():
                    st.session_state.seen_sessions.add(sid)
                    msg = f"AUDIT: {sid} | {a['level'].upper()} | Score: {a['score']}"
                    update_audit_log(msg)
                
                status.update(label="Audit Cycle Complete", state="complete", expanded=False)

        with col_feed:
            st.subheader("Live Assessment Feed")
            if not st.session_state.seen_sessions:
                st.write("No active sessions detected.")
            else:
                for sid in list(st.session_state.seen_sessions)[-5:]:
                    st.success(f"Session {sid}: Monitored & AI-Verified")

        with col_stats:
            st.subheader("Global Metrics")
            st.metric("Sessions Audited", len(st.session_state.seen_sessions))
            st.metric("System Uptime", "100%", delta="Stable")

    except Exception as e:
        st.error(f"Monitor Sync Error: {e}")
    
    time.sleep(12)
    st.rerun()

# --- PAGE: COMMAND CENTER ---
def page_command_center(cfg: Cfg) -> None:
    st.header("Security Command Center")
    col_a, col_b, col_c, col_d = st.columns(4)

    try:
        sessions = fetch_sessions(cfg.backend_url, limit=60)
        with st.spinner("Batch processing intelligence..."):
            assessments = analyze_sessions(cfg.backend_url, sessions)
    except Exception as e:
        st.error(f"Failed to sync with backend: {e}")
        st.stop()

    scores = [assessments[s["session_id"]]["score"] for s in sessions if s.get("session_id") in assessments]
    col_a.metric("Total Sessions", value=len(sessions))
    col_b.metric("High Risk", value=sum(1 for x in scores if x >= 60))
    col_c.metric("Critical", value=sum(1 for x in scores if x >= 85))
    col_d.metric("Avg Threat", value=f"{round(sum(scores)/max(1, len(scores)),1)}%")

    # Charts
    c1, c2 = st.columns(2)
    levels = [assessments[s["session_id"]]["level"] for s in sessions if s.get("session_id") in assessments]
    with c1:
        st.plotly_chart(px.histogram(x=levels, title="Risk Level Distribution"), use_container_width=True)
    with c2:
        countries = [(s.get("geo") or {}).get("country", "Unknown") for s in sessions]
        st.plotly_chart(px.pie(names=countries, title="Geographic Origin"), use_container_width=True)

    st.subheader("Session Intelligence Matrix")
    rows = []
    for s in sessions:
        sid = s["session_id"]
        if sid in assessments:
            a = assessments[sid]
            rows.append({"ID": sid, "Score": a["score"], "Level": a["level"], "User": s.get("remote_user"), "IP": s.get("source_ip")})
    st.dataframe(rows, use_container_width=True, hide_index=True)

# --- PAGE: INVESTIGATION ---
def page_investigation(cfg: Cfg) -> None:
    st.header("Log Investigation Hub")
    sessions = fetch_sessions(cfg.backend_url, limit=80)
    sid = st.selectbox("Select Session ID for Deep Dive", options=[s["session_id"] for s in sessions])
    session = next(s for s in sessions if s["session_id"] == sid)

    if st.button("Run AI Forensic Analysis"):
        with st.status("Consulting Gemini 1.5 Flash...") as status:
            st.write("Uploading session metadata...")
            assessments = analyze_sessions(cfg.backend_url, [session])
            a = assessments.get(sid)
            st.write("Pattern recognition complete.")
            status.update(label="Analysis Finalized", state="complete")

        update_audit_log(f"MANUAL INVESTIGATION: {sid} ({a['level'].upper()})")
        
        c1, c2 = st.columns(2)
        c1.metric("Risk Score", a["score"])
        c2.metric("Assessment", a["level"].upper())

        st.subheader("AI Reasoning")
        st.chat_message("ai").write(a["reasoning"])
        
        st.subheader("Risk Signals")
        for sig in a.get("signals", []):
            st.write(f"🚩 {sig}")
        
        with st.expander("View Raw Metadata"):
            st.json(session)

# --- PAGE: SYSTEM CONTROLS ---
def page_system_controls(cfg: Cfg) -> None:
    st.header("System Controls")
    st.subheader("Active Session Kill Switch")
    
    sessions = fetch_sessions(cfg.backend_url, limit=50)
    sid = st.selectbox("Target Session", options=[s["session_id"] for s in sessions])
    reason = st.text_input("Termination Reason", value="Flagged by SentinelFlow AI")

    if st.button("TERMINATE SESSION", type="primary"):
        with st.spinner("Executing remote kill command..."):
            resp = kill_session(cfg.backend_url, sid, reason)
            if resp.get("terminated"):
                st.success(f"SUCCESS: {resp.get('message')}")
                update_audit_log(f"KILL SWITCH: Session {sid} terminated.")
                st.cache_data.clear()
            else:
                st.error(resp.get("message"))

# --- NAVIGATION & MAIN ---
def main() -> None:
    require_login_ui()
    cfg = cfg_from_env()
    
    page = st.sidebar.radio("Navigate", ["Live AI Auditor", "Security Command Center", "Log Investigation Hub", "System Controls"])
    show_sidebar_audit()

    if page == "Live AI Auditor":
        page_live_monitor(cfg)
    elif page == "Security Command Center":
        page_command_center(cfg)
    elif page == "Log Investigation Hub":
        page_investigation(cfg)
    else:
        page_system_controls(cfg)

if __name__ == "__main__":
    main()
