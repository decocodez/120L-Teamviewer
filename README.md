# SentinelFlow AI (MVP)

Pure-Python security intelligence dashboard that audits remote desktop activity via the TeamViewer REST API and Gemini.

## Quickstart

### 1) Create venv + install deps

```bash
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2) Configure environment

Create a `.env` in the project root:

```env
# Backend
SENTINELFLOW_LOGIN_USERNAME=admin
SENTINELFLOW_LOGIN_PASSWORD=admin
SENTINELFLOW_BACKEND_URL=http://127.0.0.1:8000

# TeamViewer
TEAMVIEWER_BASE_URL=https://webapi.teamviewer.com/api/v1
TEAMVIEWER_API_TOKEN=  # optional; if empty, backend uses mock data

# Gemini (Google GenAI)
GEMINI_API_KEY=         # optional; if empty, backend uses heuristic scoring
GEMINI_MODEL=gemini-1.5-flash
```

### 3) Run backend

```bash
uvicorn backend.app.main:app --reload --port 8000
```

Open interactive docs at `http://127.0.0.1:8000/docs`.

### 4) Run frontend

```bash
streamlit run frontend/app.py
```

## Notes

- If `TEAMVIEWER_API_TOKEN` is not set, the backend serves deterministic mock sessions so you can demo UI + kill switch flows.
- If `GEMINI_API_KEY` is not set, the backend produces a heuristic risk score and reasoning instead of calling Gemini.

