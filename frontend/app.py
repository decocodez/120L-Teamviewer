from __future__ import annotations

from dataclasses import dataclass

import httpx
import plotly.express as px
import streamlit as st


@dataclass(frozen=True)
class Cfg:
    backend_url: str
    username: str


def _get_secret(key: str) -> str | None:
    try:
        return str(st.secrets.get(key))  # type: ignore[attr-defined]
    except Exception:
        return None


def cfg_from_env() -> Cfg:
    backend_url = _get_secret("SENTINELFLOW_BACKEND_URL") or _env("SENTINELFLOW_BACKEND_URL", "https://sentinelflow-backend.onrender.com/")
    username = _get_secret("SENTINELFLOW_LOGIN_USERNAME") or _env("SENTINELFLOW_LOGIN_USERNAME", "admin")
    return Cfg(backend_url=backend_url.rstrip("/"), username=username)


def _env(key: str, default: str) -> str:
    import os

    return os.environ.get(key, default)


def is_logged_in() -> bool:
    return bool(st.session_state.get("sf_logged_in"))


def require_login_ui() -> None:
    st.set_page_config(page_title="SentinelFlow AI", layout="wide")
    st.title("SentinelFlow AI")
    st.caption("Security intelligence dashboard for remote desktop auditing.")

    if is_logged_in():
        st.success("Logged in.")
        return

    cfg = cfg_from_env()
    expected_user = cfg.username
    expected_pass = _get_secret("SENTINELFLOW_LOGIN_PASSWORD") or _env("SENTINELFLOW_LOGIN_PASSWORD", "admin")

    with st.form("login"):
        st.subheader("Login Gate")
        u = st.text_input("Username", value="", autocomplete="username")
        p = st.text_input("Password", value="", type="password", autocomplete="current-password")
        submitted = st.form_submit_button("Login")
        if submitted:
            if u == expected_user and p == expected_pass:
                st.session_state["sf_logged_in"] = True
                st.session_state["sf_user"] = u
                st.rerun()
            else:
                st.error("Invalid credentials.")

    st.stop()


def backend_headers() -> dict[str, str]:
    return {"X-SentinelFlow-User": st.session_state.get("sf_user", "")}


@st.cache_data(ttl=10)
def fetch_sessions(backend_url: str, limit: int = 50) -> list[dict]:
    r = httpx.get(f"{backend_url}/sessions", headers=backend_headers(), params={"limit": limit}, timeout=20)
    r.raise_for_status()
    return r.json()


def analyze_sessions(backend_url: str, sessions: list[dict]) -> dict[str, dict]:
    r = httpx.post(f"{backend_url}/analyze", headers=backend_headers(), json={"sessions": sessions}, timeout=60)
    r.raise_for_status()
    return r.json()["assessments"]


def kill_session(backend_url: str, session_id: str, reason: str | None) -> dict:
    r = httpx.post(f"{backend_url}/kill", headers=backend_headers(), json={"session_id": session_id, "reason": reason}, timeout=20)
    r.raise_for_status()
    return r.json()


def nav() -> str:
    st.sidebar.title("SentinelFlow AI")
    return st.sidebar.radio(
        "Navigate",
        options=[
            "Security Command Center",
            "Log Investigation Hub",
            "System Controls",
        ],
    )


def page_command_center(cfg: Cfg) -> None:
    st.header("Security Command Center")

    col_a, col_b, col_c, col_d = st.columns(4)
    try:
        sessions = fetch_sessions(cfg.backend_url, limit=60)
    except Exception as e:  # noqa: BLE001
        st.error(f"Failed to fetch sessions from backend: {e}")
        st.stop()

    with st.spinner("Analyzing sessions..."):
        assessments = analyze_sessions(cfg.backend_url, sessions)

    scores = [assessments[s["session_id"]]["score"] for s in sessions if s.get("session_id") in assessments]
    highs = sum(1 for x in scores if x >= 60)
    criticals = sum(1 for x in scores if x >= 85)

    col_a.metric("Sessions (loaded)", value=str(len(sessions)))
    col_b.metric("High+", value=str(highs))
    col_c.metric("Critical", value=str(criticals))
    col_d.metric("Avg score", value=str(round(sum(scores) / max(1, len(scores)), 1)))

    levels = [assessments[s["session_id"]]["level"] for s in sessions if s.get("session_id") in assessments]
    countries = []
    for s in sessions:
        geo = s.get("geo") or {}
        countries.append((geo.get("country") or "Unknown") if isinstance(geo, dict) else "Unknown")

    viz_a, viz_b = st.columns(2)
    with viz_a:
        if levels:
            fig = px.histogram(x=levels, category_orders={"x": ["low", "medium", "high", "critical"]}, title="Risk levels")
            st.plotly_chart(fig, use_container_width=True)
    with viz_b:
        if countries:
            fig = px.pie(names=countries, title="Country distribution")
            st.plotly_chart(fig, use_container_width=True)

    st.subheader("Top risky sessions")
    rows = []
    for s in sessions:
        sid = s.get("session_id")
        if not sid or sid not in assessments:
            continue
        a = assessments[sid]
        rows.append(
            {
                "session_id": sid,
                "score": a["score"],
                "level": a["level"],
                "remote_user": s.get("remote_user"),
                "device_id": s.get("device_id"),
                "source_ip": s.get("source_ip"),
                "start_time": s.get("start_time"),
                "end_time": s.get("end_time"),
            }
        )
    rows.sort(key=lambda r: r["score"], reverse=True)
    st.dataframe(rows[:25], use_container_width=True, hide_index=True)


def page_investigation(cfg: Cfg) -> None:
    st.header("Log Investigation Hub")

    try:
        sessions = fetch_sessions(cfg.backend_url, limit=80)
    except Exception as e:  # noqa: BLE001
        st.error(f"Failed to fetch sessions from backend: {e}")
        st.stop()

    sid = st.selectbox("Select session", options=[s["session_id"] for s in sessions])
    session = next(s for s in sessions if s["session_id"] == sid)

    with st.spinner("Generating AI threat reasoning..."):
        assessments = analyze_sessions(cfg.backend_url, [session])
        a = assessments.get(sid)

    if not a:
        st.warning("No assessment returned.")
        st.stop()

    col1, col2 = st.columns([1, 1])
    col1.metric("Risk score", value=str(a["score"]))
    col2.metric("Level", value=str(a["level"]).upper())

    st.subheader("AI reasoning")
    with st.chat_message("ai"):
        st.write(a["reasoning"])

    st.subheader("Signals")
    for sig in a.get("signals") or []:
        st.write(f"- {sig}")

    with st.expander("Session metadata (raw)"):
        st.json(session)


def page_system_controls(cfg: Cfg) -> None:
    st.header("System Controls")
    st.subheader("REST Kill Switch")

    try:
        sessions = fetch_sessions(cfg.backend_url, limit=80)
    except Exception as e:  # noqa: BLE001
        st.error(f"Failed to fetch sessions from backend: {e}")
        st.stop()

    sid = st.selectbox("Session to terminate", options=[s["session_id"] for s in sessions])
    reason = st.text_input("Reason (optional)", value="Suspicious activity flagged by SentinelFlow AI")

    col1, col2 = st.columns([1, 3])
    if col1.button("Terminate session", type="primary"):
        with st.spinner("Sending termination request..."):
            try:
                resp = kill_session(cfg.backend_url, sid, reason=reason or None)
                if resp.get("terminated"):
                    st.success(resp.get("message"))
                    st.cache_data.clear()
                else:
                    st.error(resp.get("message"))
            except Exception as e:  # noqa: BLE001
                st.error(f"Kill switch failed: {e}")

    col2.caption("This calls the backend `/kill` endpoint, which forwards termination to TeamViewer when configured.")


def main() -> None:
    require_login_ui()
    cfg = cfg_from_env()

    page = nav()
    if page == "Security Command Center":
        page_command_center(cfg)
    elif page == "Log Investigation Hub":
        page_investigation(cfg)
    else:
        page_system_controls(cfg)


if __name__ == "__main__":
    main()

